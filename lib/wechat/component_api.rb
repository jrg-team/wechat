# frozen_string_literal: true

require 'wechat/api_base'
require 'wechat/http_client'
require 'wechat/token/component_access_token'
require 'wechat/ticket/component_verify_ticket'

module Wechat
  class ComponentApi < ApiBase
    attr_reader :component_appid, :component_secret, :component_verify_ticket_file, :verify_ticket
    attr_accessor :authorizer_token_updated_callback
    def initialize(
        component_appid,
        component_secret,
        component_token_file,
        component_verify_ticket_file,
        timeout,
        skip_verify_ssl,
        authorizer_token_updated_callback = nil
    )
      super()
      @client = HttpClient.new(Wechat::Api::COMPONENT_API_BASE, timeout, skip_verify_ssl)
      @access_token = Token::ComponentAccessToken.new(
          @client,
          component_appid,
          component_secret,
          component_token_file,
          component_verify_ticket_file,
          'component_access_token'
      )
      @verify_ticket = Ticket::ComponentVerifyTicket.new(component_verify_ticket_file)
      @component_appid = component_appid
      @component_secret = component_secret
      @component_verify_ticket_file = component_verify_ticket_file
      @authorizer_token_updated_callback = authorizer_token_updated_callback
    end

    def start_push_ticket
      params = {
          component_appid: component_appid,
          component_secret: component_secret
      }.to_json
      client.post 'api_start_push_ticket', params, base: Wechat::Api::COMPONENT_API_BASE
    end

    # update verify ticket
    def save_verify_ticket(ticket, create_time)
      verify_ticket.update({verify_ticket: ticket, create_time: create_time}.stringify_keys)
    end

    # update verify ticket
    def get_pre_auth_code
      get 'api_create_preauthcode', params: {component_appid: component_appid}
    end

    # get auth url, redirect_to should not be encoded
    def get_auth_url(redirect_to)
      result = get_pre_auth_code
      pre_auto_code = result.stringify_keys["pre_auth_code"]
      return "https://mp.weixin.qq.com/cgi-bin/componentloginpage?component_appid=#{component_appid}&pre_auth_code=#{pre_auto_code}&redirect_uri=#{URI.encode(redirect_to)}&auth_type=1", pre_auto_code
    end

    # get authorization details
    def get_auth_details_by_authorization_code(code)
      result = get 'api_query_auth', params: {
          component_appid: component_appid,
          authorization_code: code
      }
      result["authorization_info"]
    end

    # get authorizer info
    def get_authorizer_info(authorizer_appid)
      result = get 'api_get_authorizer_info', params: {
          component_appid: component_appid,
          authorizer_appid: authorizer_appid
      }
      result["authorizer_info"]
    end

    def refresh_authorizer_token(auth_hash)
      post 'api_authorizer_token',
           JSON.generate(
               component_appid: component_appid,
               authorizer_appid: auth_hash['appid'],
               authorizer_refresh_token: auth_hash['refresh_token']
           )
    end

    # set_industry
    def set_industry_for_authorizer(auth_hash = {}, industry_ids = [1, 2])
      commission_post auth_hash,
                      'template/api_set_industry',
                      JSON.generate(
                          industry_id1: industry_ids[0],
                          industry_id2: industry_ids[1],
                      ),
                      base: Wechat::Api::API_BASE
    end

    # add template
    def add_message_template_for_authorizer(auth_hash = {}, template_id_short)
      commission_post auth_hash,
                      'template/api_add_template',
                      JSON.generate(template_id_short: template_id_short),
                      base: Wechat::Api::API_BASE
    end

    # get all template
    def get_all_templates_for_authorizer(auth_hash = {})
      commission_get auth_hash, 'template/get_all_private_template',
                     base: Wechat::Api::WXA_API_BASE
    end

    # add template, return [result, auth_hash]
    def send_template_message_for_authorizer(auth_hash = {}, message)
      commission_post auth_hash,
                      'message/template/send',
                      message.to_json,
                      content_type: :json,
                      base: Wechat::Api::WXA_API_BASE
    end

    protected

    def with_access_token(params = {}, tries = 2)
      params ||= {}
      yield(params.merge(component_access_token: access_token.token))
    rescue AccessTokenExpiredError
      access_token.refresh
      retry unless (tries -= 1).zero?
    end

    def update_authorizer_access_token(auth_hash = {})
      auth_hash = auth_hash.stringify_keys
      token_updated_at = auth_hash['token_updated_at']
      if (Time.now.to_i - token_updated_at.to_i) > 12.hours.to_i
        raise InvalidCredentialError
      else
        refresh_authorizer_token(auth_hash)
      end
    end

    def with_authorizer_access_token(auth_hash = {}, params = {}, tries = 2)
      raise InvalidCredentialError unless auth_hash.is_a?(Hash) && auth_hash["access_token"] && auth_hash["appid"]
      token = auth_hash["access_token"]
      result = yield(params.merge(access_token: token))
      return result, auth_hash
    rescue AccessTokenExpiredError
      update_result = update_authorizer_access_token(auth_hash)
      auth_hash["access_token"] = update_result['authorizer_access_token']
      auth_hash["refresh_token"] = update_result['authorizer_refresh_token']
      auth_hash["token_updated_at"] = Time.now
      retry unless (tries -= 1).zero?
    end

    def commission_get(auth_hash, path, headers = {})
      origin_auth = auth_hash.clone
      result, new_auth = with_authorizer_access_token(auth_hash, headers[:params]) do |params|
        client.get path, headers.merge(params: params)
      end
      compare_and_execute_update_callback(origin_auth, new_auth)
      result
    end

    def commission_post(auth_hash, path, payload, headers = {})
      origin_auth = auth_hash.clone
      result, new_auth = with_authorizer_access_token(auth_hash, headers[:params]) do |params|
        client.post path, payload, headers.merge(params: params)
      end
      compare_and_execute_update_callback(origin_auth, new_auth)
      result
    end

    def compare_and_execute_update_callback(old_hash, new_hash)
      if old_hash["token_updated_at"]&.to_i != new_hash["token_updated_at"]&.to_i
        authorizer_token_updated_callback&.call(new_hash)
      end
    end
  end
end

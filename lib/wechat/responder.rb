# frozen_string_literal: true

require 'English'
require 'wechat/signature'

module Wechat
  module Responder
    extend ActiveSupport::Concern
    include Wechat::ControllerApi
    include Cipher

    included do
      # Rails 5 remove before_filter and skip_before_filter
      if respond_to?(:skip_before_action)
        if respond_to?(:verify_authenticity_token)
          skip_before_action :verify_authenticity_token
        else
          # Rails 5 API mode won't define verify_authenticity_token
          # https://github.com/rails/rails/blob/v5.0.0.beta3/actionpack/lib/abstract_controller/callbacks.rb#L66
          # https://github.com/rails/rails/blob/v5.0.0.beta3/activesupport/lib/active_support/callbacks.rb#L640
          skip_before_action :verify_authenticity_token, raise: false
        end

        before_action :config_account, only: %i[show create]
        before_action :verify_signature, only: %i[show create]
      else
        skip_before_filter :verify_authenticity_token
        before_filter :config_account, only: %i[show create]
        before_filter :verify_signature, only: %i[show create]
      end
    end

    module ClassMethods
      attr_accessor :account_from_request

      def on(message_type, with: nil, respond: nil, &block)
        raise 'Unknow message type' unless %i[text image voice video shortvideo link event click view scan batch_job location label_location fallback component].include?(message_type)

        config = respond.nil? ? {} : { respond: respond }
        config[:proc] = block if block_given?

        if with.present?
          raise 'Only text, event, click, view, scan, batch_job and component can having :with parameters' unless %i[text event click view scan batch_job component].include?(message_type)

          config[:with] = with
          if message_type == :scan
            raise 'on :scan only support string in parameter with, detail see https://github.com/Eric-Guo/wechat/issues/84' unless with.is_a?(String)

            self.known_scan_key_lists = with
          end
        elsif %i[click view scan batch_job component].include?(message_type)
          raise 'Message type click, view, scan, batch_job and component must specify :with parameters'
        end

        case message_type
        when :click
          user_defined_click_responders(with) << config
        when :view
          user_defined_view_responders(with) << config
        when :batch_job
          user_defined_batch_job_responders(with) << config
        when :scan
          user_defined_scan_responders << config
        when :location
          user_defined_location_responders << config
        when :label_location
          user_defined_label_location_responders << config
        when :component
          user_defined_component_responders(with) << config
        else
          user_defined_responders(message_type) << config
        end

        config
      end

      def user_defined_click_responders(with)
        @click_responders ||= {}
        @click_responders[with] ||= []
      end

      def user_defined_view_responders(with)
        @view_responders ||= {}
        @view_responders[with] ||= []
      end

      def user_defined_batch_job_responders(with)
        @batch_job_responders ||= {}
        @batch_job_responders[with] ||= []
      end

      def user_defined_scan_responders
        @user_defined_scan_responders ||= []
      end

      def user_defined_location_responders
        @user_defined_location_responders ||= []
      end

      def user_defined_label_location_responders
        @user_defined_label_location_responders ||= []
      end

      def user_defined_responders(type)
        @responders ||= {}
        @responders[type] ||= []
      end

      def user_defined_component_responders(type)
        @component_responders ||= {}
        @component_responders[type] ||= []
      end

      def responder_for(message)
        message_type = message[:MsgType]&.to_sym
        if message[:InfoType].present?
          message_type ||= :component
        end
        responders = user_defined_responders(message_type)
        case message_type
        when :text
          yield(* match_responders(responders, message[:Content]))
        when :component
          yield(* user_defined_component_responders(message[:InfoType]), message[:InfoType])
        when :event
          if message[:Event] == 'click' && !user_defined_click_responders(message[:EventKey]).empty?
            yield(* user_defined_click_responders(message[:EventKey]), message[:EventKey])
          elsif message[:Event] == 'view' && !user_defined_view_responders(message[:EventKey]).empty?
            yield(* user_defined_view_responders(message[:EventKey]), message[:EventKey])
          elsif message[:Event] == 'click'
            yield(* match_responders(responders, message[:EventKey]))
          elsif known_scan_key_lists.include?(message[:EventKey]) && %w[scan subscribe scancode_push scancode_waitmsg].freeze.include?(message[:Event])
            yield(* known_scan_with_match_responders(user_defined_scan_responders, message))
          elsif message[:Event] == 'batch_job_result'
            yield(* user_defined_batch_job_responders(message[:BatchJob][:JobType]), message[:BatchJob])
          elsif message[:Event] == 'location'
            yield(* user_defined_location_responders, message)
          else
            yield(* match_responders(responders, message[:Event]))
          end
        when :location
          yield(* user_defined_label_location_responders, message)
        else
          yield(responders.first)
        end
      end

      private

      def match_responders(responders, value)
        matched = responders.each_with_object({}) do |responder, memo|
          condition = responder[:with]

          if condition.nil?
            memo[:general] ||= [responder, value]
            next
          end

          case condition
          when Regexp
            memo[:scoped] ||= [responder] + $LAST_MATCH_INFO.captures if value =~ condition
          when value
            memo[:scoped] ||= [responder, value]
          end
        end
        matched[:scoped] || matched[:general]
      end

      def known_scan_with_match_responders(responders, message)
        matched = responders.each_with_object({}) do |responder, memo|
          if %w[scan subscribe].freeze.include?(message[:Event]) && message[:EventKey] == responder[:with]
            memo[:scaned] ||= [responder, message[:Ticket]]
          elsif %w[scancode_push scancode_waitmsg].freeze.include?(message[:Event]) && message[:EventKey] == responder[:with]
            memo[:scaned] ||= [responder, message[:ScanCodeInfo][:ScanResult], message[:ScanCodeInfo][:ScanType]]
          end
        end
        matched[:scaned]
      end

      def known_scan_key_lists
        @known_scan_key_lists ||= []
      end

      def known_scan_key_lists=(qrscene_value)
        @known_scan_key_lists ||= []
        @known_scan_key_lists << qrscene_value
      end
    end

    def show
      if @we_corpid.present?
        echostr, _corp_id = unpack(decrypt(Base64.decode64(params[:echostr]), @we_encoding_aes_key))
        if Rails::VERSION::MAJOR >= 4
          render plain: echostr
        else
          render text: echostr
        end
      elsif Rails::VERSION::MAJOR >= 4
        render plain: params[:echostr]
      else
        render text: params[:echostr]
      end
    end

    def create
      request_msg = Wechat::Message.from_hash(post_xml)
      response_msg = run_responder(request_msg)

      if response_msg.respond_to? :to_xml
        if Rails::VERSION::MAJOR >= 4
          render plain: process_response(response_msg)
        else
          render text: process_response(response_msg)
        end
      else
        head :ok, content_type: 'text/html'
      end

      if response_msg.is_a?(Wechat::Message) && Wechat.config.have_session_class && request_msg[:InfoType].blank?
        response_msg.save_session
      end

      ActiveSupport::Notifications.instrument 'wechat.responder.after_create', request: request_msg, response: response_msg
    end

    private

    def config_account
      account = self.class.account_from_request&.call(request)
      config = account ? Wechat.config(account) : nil

      @we_encrypt_mode = config&.encrypt_mode || self.class.encrypt_mode
      @we_encoding_aes_key = config&.encoding_aes_key || self.class.encoding_aes_key
      @we_token = config&.token || self.class.token
      @we_corpid = config&.corpid || self.class.corpid
    end

    def verify_signature
      if @we_encrypt_mode
        signature = params[:signature] || params[:msg_signature]
        msg_encrypt = params[:echostr] || request_encrypt_content
      else
        signature = params[:signature]
      end

      msg_encrypt = nil unless @we_corpid.present?

      render plain: 'Forbidden', status: 403 if signature != Signature.hexdigest(@we_token,
                                                                                 params[:timestamp],
                                                                                 params[:nonce],
                                                                                 msg_encrypt)
    end

    def post_xml
      data = request_content

      if @we_encrypt_mode && request_encrypt_content.present?
        content, @we_app_id = unpack(decrypt(Base64.decode64(request_encrypt_content), @we_encoding_aes_key))
        data = Hash.from_xml(content)
      end

      data_hash = data.fetch('xml', {})
      if Rails::VERSION::MAJOR >= 5
        data_hash = data_hash.to_unsafe_hash if data_hash.instance_of?(ActionController::Parameters)
        HashWithIndifferentAccess.new(data_hash).tap do |msg|
          msg[:Event]&.downcase!
        end
      else
        HashWithIndifferentAccess.new_from_hash_copying_default(data_hash).tap do |msg|
          msg[:Event]&.downcase!
        end
      end
    end

    def run_responder(request)
      self.class.responder_for(request) do |responder, *args|
        responder ||= self.class.user_defined_responders(:fallback).first

        next if responder.nil?

        if responder[:respond]
          request.reply.text responder[:respond]
        elsif responder[:proc]
          define_singleton_method :process, responder[:proc]
          number_of_block_parameter = responder[:proc].arity
          send(:process, *args.unshift(request).take(number_of_block_parameter))
        else
          next
        end
      end
    end

    def process_response(response)
      msg = response[:MsgType] == 'success' ? 'success' : response.to_xml

      if @we_encrypt_mode
        encrypt = Base64.strict_encode64(encrypt(pack(msg, @we_app_id), @we_encoding_aes_key))
        msg = gen_msg(encrypt, params[:timestamp], params[:nonce])
      end

      msg
    end

    def gen_msg(encrypt, timestamp, nonce)
      msg_sign = Signature.hexdigest(@we_token, timestamp, nonce, encrypt)

      { Encrypt: encrypt,
        MsgSignature: msg_sign,
        TimeStamp: timestamp,
        Nonce: nonce }.to_xml(root: 'xml', children: 'item', skip_instruct: true, skip_types: true)
    end

    def request_encrypt_content
      request_content&.dig('xml', 'Encrypt')
    end

    def request_content
      params[:xml].nil? ? Hash.from_xml(request.raw_post) : { 'xml' => params[:xml] }
    end
  end
end

require 'digest/sha1'

module Wechat
  module Ticket
    class JsapiBase
      attr_reader :client, :access_token, :jsapi_ticket_file, :access_ticket, :ticket_life_in_seconds, :got_ticket_at

      def initialize(client, access_token, jsapi_ticket_file)
        @client = client
        @access_token = access_token
        @jsapi_ticket_file = jsapi_ticket_file
        @random_generator = Random.new
      end

      def ticket
        # Possible two worker running, one worker refresh ticket, other unaware, so must read every time
        read_ticket_from_file
        refresh if remain_life_seconds < @random_generator.rand(30..3 * 60)
        access_ticket
      end

      # Obtain the wechat jssdk config signature parameter and return below hash
      #  params = {
      #    noncestr: noncestr,
      #    timestamp: timestamp,
      #    jsapi_ticket: ticket,
      #    url: url,
      #    signature: signature
      #  }
      def signature(url)
        params = {
          noncestr: SecureRandom.base64(16),
          timestamp: Time.now.to_i,
          jsapi_ticket: ticket,
          url: url
        }
        pairs = params.keys.sort.map do |key|
          "#{key}=#{params[key]}"
        end
        result = Digest::SHA1.hexdigest pairs.join('&')
        params.merge(signature: result)
      end

      protected

      def read_ticket_from_file
        td = JSON.parse(File.read(jsapi_ticket_file))
        @got_ticket_at = td.fetch('got_ticket_at').to_i
        @ticket_life_in_seconds = td.fetch('expires_in').to_i
        @access_ticket = td.fetch('ticket')
      rescue JSON::ParserError, Errno::ENOENT, KeyError
        refresh
      end

      def write_ticket_to_file(ticket_hash)
        ticket_hash.merge!('got_ticket_at'.freeze => Time.now.to_i)
        File.write(jsapi_ticket_file, ticket_hash.to_json)
      end

      def remain_life_seconds
        ticket_life_in_seconds - (Time.now.to_i - got_ticket_at)
      end
    end
  end
end
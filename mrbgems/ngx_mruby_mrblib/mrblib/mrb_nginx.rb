class Nginx
  class Request
    def scheme
      self.var.scheme
    end

    def document_root
      Nginx::Server.new.document_root
    end

    def body
      self.read_body
      self.get_body
    end

    def uri_args
      args_to_hash(self.args)
    end

    def uri_args=(params)
      raise ArgumentError unless params.is_a?(Hash)
      self.args = params.map{|k,v| "#{k}=#{v}"}.join("&")
    end

    def post_args
      args_to_hash(self.body)
    end

    private

    def args_to_hash(args)
      Hash[*args.split("&").map{|arg| arg.split("=")}.flatten]
    end
  end

  class Headers_in
    def user_agent
      self["User-Agent"]
    end
  end

  def self.var
    Var.new
  end
end

module Kernel
  def get_server_class
    Nginx
  end

  def _ngx_mruby_prepare_fiber(app_proc)
    fiber = Fiber.new do
      app_proc.call
    end

    Proc.new do
      rv = fiber.resume
      is_alive = fiber.alive?
      [is_alive, rv]
    end
  end
end

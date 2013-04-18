#!/usr/bin/env ruby
require "base64"
require "rack"

SECRET = "secret, dont tell anyone"

def generate_auth_token(data)
  Digest::SHA1.hexdigest(SECRET + data)
end

def authenticate(data, auth_token)
  generate_auth_token(data) == auth_token
end

def response(body, code=200)
  [ code, { "Content-Type" => "text/html" }, [ body ] ]
end

def guest_url
  data = 'user=guest,admin=false'
  "/?user=" + Base64.urlsafe_encode64(data) + "&auth=" + generate_auth_token(data)
end

def page(head, body="", code=200)
  return response("<h2>#{head}</h2>\n<p>#{body}</p>", code)
end

def parse_query_string(env)
  env['QUERY_STRING'].split(/\&/).map{ |kv| kv.split("=", 2) }.inject(Hash.new){ |h,a| h[a[0]] = a[1]; h }
end

def respond(env)
  params = parse_query_string(env)
  return page("User data missing!", 'Log in as <a href="' + guest_url() + '">guest</a>') unless params["user"]
  return page("Auth data missing!") unless params["auth"]

  begin
    data = Base64.urlsafe_decode64(params["user"])
  rescue
    return page("Failed to decode user data")
  end

  ##### AUTHENTICATION FAIL!
  unless authenticate(data, params["auth"])
    puts "Invalid auth from #{ENV['REMOTE_ADDR']}: " + [ data, params, generate_auth_token(data) ].inspect
    return page("Authentication failed!", "What the f... are you doing??", 403)
  end

  ##### PARSER FAIL!
  parsed = {}
  data = data.split(",").map{ |kv| kv.split("=") }
  data.each do |key, value|
    parsed[key] = value
  end

  if parsed["admin"] == "true"
    return page("Welcome #{parsed["user"]}, you are an <font color='red'>admin</font>!!!1", "Click <a href='#'>here</a> to do evil stuff.")
  end

  return page("What's up, #{parsed["user"]}?", "Nothing to see. Go home.")
end

thin = Rack::Handler.get('thin')
thin.run(method(:respond), :Port => 3000)

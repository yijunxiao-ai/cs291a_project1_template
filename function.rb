# frozen_string_literal: true

require 'json'
require 'jwt'
require 'pp'

def main(event:, context:)
  # You shouldn't need to use context, but its fields are explained here:
  # https://docs.aws.amazon.com/lambda/latest/dg/ruby-context.html
  if event["path"] == "/"
    if event["httpMethod"] == "GET"
      responseGetRoot(event: event)
    else
      response(body: event, status: 405)
    end
  elsif event["path"] == "/token"
    if event["httpMethod"] == "POST"
      responsePostToken(event: event)
    else
      response(body: event, status: 405)
    end
  else
    response(body: event, status: 404)
  end
end

def responseGetRoot(event:)
  if not event.key?("headers")
    response(body: event, status: 403)
  elsif not event["headers"].key?("Authorization")
    response(body: event, status: 403)
  elsif not event["headers"]["Authorization"].start_with?("Bearer ")
    response(body: event, status: 403)
  else
    token = event["headers"]["Authorization"][7..-1]
    begin
      decoded_token = JWT.decode token, ENV["JWT_SECRET"], true, { algorithm: 'HS256' }
    rescue JWT::ExpiredSignature
      response(body: event, status: 401)
    rescue JWT::ImmatureSignature
      response(body: event, status: 401)
    else
      response(body: decoded_token[0]["data"], status: 200)
    end
  end
end

def responsePostToken(event:)
  if event["headers"]["Content-Type"] != "application/json"
    response(status: 415)
  else
    body = event["body"]
    begin
      JSON.parse(body)
    rescue Exception => e
      response(status: 422)
    else
      token = generateToken(body: body)
      response(body: {"token" => token}, status: 201)
    end
  end
end

def generateToken(body:)
  payload = {
    data: body,
    exp: Time.now.to_i + 5,
    nbf: Time.now.to_i + 2
  }
  token = JWT.encode payload, ENV["JWT_SECRET"], "HS256"
  return token
end

def response(body: nil, status: 200)
  {
    body: body ? body.to_json + "\n" : '',
    statusCode: status
  }
end

if $PROGRAM_NAME == __FILE__
  # If you run this file directly via `ruby function.rb` the following code
  # will execute. You can use the code below to help you test your functions
  # without needing to deploy first.
  ENV['JWT_SECRET'] = 'NOTASECRET'

  # Call /token
  PP.pp main(context: {}, event: {
               'body' => '{"name": "bboe"}',
               'headers' => { 'Content-Type' => 'application/json' },
               'httpMethod' => 'POST',
               'path' => '/token'
             })

  # Generate a token
  payload = {
    data: { user_id: 128 },
    exp: Time.now.to_i + 1,
    nbf: Time.now.to_i
  }
  token = JWT.encode payload, ENV['JWT_SECRET'], 'HS256'
  # Call /
  PP.pp main(context: {}, event: {
               'headers' => { 'Authorization' => "Bearer #{token}",
                              'Content-Type' => 'application/json' },
               'httpMethod' => 'GET',
               'path' => '/'
             })
end

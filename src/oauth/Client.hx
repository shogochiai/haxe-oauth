package oauth;

import haxe.Json;
import oauth.Tokens;

class Client {

	public var version(default, null):OAuthVersion;
	public var consumer(default, null):Consumer;
	public var accessToken:Null<AccessToken>;

	public function new (version:OAuthVersion, consumer:Consumer) {
		this.version = version;
		this.consumer = consumer;
	}

	/*
	public function getRequestToken (uri:String, callback:String, ?post:Bool = true):RequestToken {
		if (!version.match(V1)) throw "Request token only applies to OAuth 1.";

		var req = new Request(version, uri, consumer, null, post, null, { oauth_callback:callback } );
		req.sign();
		var result = strToMap(req.send());

		if (!result.exists("oauth_token")) throw "Failed to get request token.";

		return new RequestToken(result.get("oauth_token"), result.get("oauth_token_secret"));
	}

	public function getAccessToken1 (uri:String, verifier:String, ?post:Bool = true):Client {
		if (!version.match(V1)) throw "Cannot call an OAuth 1 method from a non-OAuth 1 flow.";

		var result = requestUrlEncoded(uri, post, { oauth_verifier:verifier });

		if (!result.exists("oauth_token") || !result.exists("oauth_token_secret")) throw "Failed to get access token.";

		accessToken = new OAuth1AccessToken(result.get("oauth_token"), result.get("oauth_token_secret"));
		return this;
	}
	*/

	public function getAccessToken2 (uri:String, code:String, redirectUri:String, ?post:Bool = true, cb:Dynamic):Void {
		if (!version.match(V2)) throw "Cannot call an OAuth 2 method from a non-OAuth 2 flow.";
		var req_param : Dynamic = {
			code:code,
			client_id:consumer.key,
			client_secret:consumer.secret,
			redirect_uri:redirectUri,
			grant_type:"authorization_code"
		}

		request(uri, post, req_param, function(response){
			var result : Map<String, String> = param_parse(response);
			// var result = jsonToMap(response);
			// if (!result.exists("access_token")) throw "Failed to get access token.";
			var client = new Client(version, consumer);

			client.accessToken = new OAuth2AccessToken(result.get("access_token"), Std.parseInt(result.get("expires_in")));
			cb(client);
		});
	}

	public function param_parse (str:String) : Map<String, String> {
		var query_seperated : Array<String> = str.split("&");
		var atoken : Array<String> = query_seperated[0].split("=");
		var expires_in : Array<String> = query_seperated[1].split("=");
		var result = new Map<String, String>();
		result["access_token"] = atoken[1];
		result["expires_in"] = expires_in[1];
		return result;
	}

	public inline function requestJSON (uri:String, ?post:Bool = false, ?postData:Dynamic, cb:Dynamic):Void {
		request(uri, post, postData, function(response){
			// fbのアクセストークンが返ってきた場合parseできない
			cb( Json.parse(response) );
		});
	}

	inline function jsonToMap (json:Dynamic):Map<String, String> {
		var map = new Map<String, String>();

		for (i in Reflect.fields(json)) {
			map.set(i, Reflect.field(json, i));
		}

		return map;
	}

	public function request (uri:String, ?post:Bool = false, ?postData:Dynamic, cb:Dynamic):Void {
		var req = new Request(version, uri, consumer, accessToken, post, postData);
		if (version == V1) req.sign();
		req.send(cb);
	}

}

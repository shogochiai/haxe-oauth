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

	inline function strToMap (str:String):Map<String, String> {
		var map = new Map<String, String>();
		for (i in str.split('&')) {
			var pair = i.split('=');
			if (pair.length >= 2) map.set(StringTools.urlDecode(pair[0]), StringTools.urlDecode(pair[1]));
		}
		return map;
	}

	public function getRequestToken (uri:String, callback:String, ?post:Bool = true, cb:RequestToken->Void):Void{
		if (!version.match(V1)) throw "Request token only applies to OAuth 1.";

		var req = new Request(version, uri, consumer, null, post, null, { oauth_callback:callback } );
		req.sign();
		req.send(function(response){
			var result:Map<String, String> = strToMap(response);
			if (!result.exists("oauth_token")) throw "Failed to get request token.";
			var rtoken:RequestToken = new RequestToken(result.get("oauth_token"), result.get("oauth_token_secret"));
			cb(rtoken);
		});
	}

	public function getAccessToken1 (uri:String, request_token:String, verifier:String, ?post:Bool = true, cb:String->String->Void):Void {
		if (!version.match(V1)) throw "Cannot call an OAuth 1 method from a non-OAuth 1 flow.";
		request(uri, post, { oauth_token: request_token, oauth_verifier:verifier }, function(result){
			if (result.indexOf("oauth_token") < 0  || result.indexOf("oauth_token_secret") < 0) throw "Failed to get access token.";
			var token_str : String = result.split("&")[0].split("=")[1];
			var secret_str : String = result.split("&")[1].split("=")[1];
			var user_id : String = result.split("&")[2].split("=")[1];
			var screen_name : String = result.split("&")[3].split("=")[1];
			var client = new Client(version, consumer);
			client.accessToken = new OAuth1AccessToken(token_str, secret_str);
			cb(user_id, screen_name);
		});
	}

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
			var result : Map<String, String> = oauth2ParamParse(response);
			// var result = jsonToMap(response);
			// if (!result.exists("access_token")) throw "Failed to get access token.";
			var client = new Client(version, consumer);

			client.accessToken = new OAuth2AccessToken(result.get("access_token"), Std.parseInt(result.get("expires_in")));
			cb(client);
		});
	}

	public function oauth2ParamParse (str:String) : Map<String, String> {
		var query_seperated : Array<String> = str.split("&");
		var atoken : Array<String> = query_seperated[0].split("=");
		var expires_in : Array<String> = query_seperated[1].split("=");
		var result = new Map<String, String>();
		result["access_token"] = if(atoken[0]=="access_token") atoken[1] else "";
		result["expires_in"] = if(atoken[0]=="expires") expires_in[1] else "";
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

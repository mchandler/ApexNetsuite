global class NetsuiteSigningService {

    private Netsuite_OAuth__c service = Netsuite_OAuth__c.getOrgDefaults();
    private String token = service.Token_Id__c;
    private String tokenSecret = service.Token_Secret__c;
    private String realm = service.Realm__c;
    private String verifier;

    private String nonce;
    private String timestamp;
    private String signature;
    private String consumerKey = service.Consumer_Key__c;
    private String consumerSecret = service.Consumer_Secret__c;

    private Map<String,String> parameters = new Map<String,String>();

    private void refreshParameters() {
        parameters.clear();
        parameters.put('realm',realm);
        parameters.put('oauth_consumer_key',consumerKey);
        if(token!=null) {
            parameters.put('oauth_token',token);
        }

        if(verifier!=null) {
            parameters.put('oauth_verifier',verifier);
        }
        parameters.put('oauth_signature_method','HMAC-SHA256');
        parameters.put('oauth_timestamp',timestamp);
        parameters.put('oauth_nonce',nonce);
        parameters.put('oauth_version','1.0');
    }

    private Map<String,String> getUrlParams(String value) {

        Map<String,String> res = new Map<String,String>();
        if(value==null || value=='') {
            return res;
        }
        for(String s : value.split('&')) {
            System.debug('getUrlParams: '+s);
            List<String> kv = s.split('=');
            if(kv.size()>1) {
                // RFC 5849 section 3.4.1.3.1 and 3.4.1.3.2 specify that parameter names
                // and values are decoded then encoded before being sorted and concatenated
                // Section 3.6 specifies that space must be encoded as %20 and not +
                String encName = EncodingUtil.urlEncode(EncodingUtil.urlDecode(kv[0], 'UTF-8'), 'UTF-8').replace('+','%20');
                String encValue = EncodingUtil.urlEncode(EncodingUtil.urlDecode(kv[1], 'UTF-8'), 'UTF-8').replace('+','%20');
                System.debug('getUrlParams:  -> '+encName+','+encValue);
                res.put(encName,encValue);
            }
        }
        return res;
    }

    private String createBaseString(Map<String,String> oauthParams, HttpRequest req) {
        Map<String,String> p = oauthParams.clone();
        p.remove('realm'); // Do not put the realm in the Base String
        String host = req.getEndpoint();
        Integer n = host.indexOf('?');
        if(n>-1) {
            p.putAll(getUrlParams(host.substring(n+1)));
            host = host.substring(0,n);
        }
        List<String> keys = new List<String>();
        keys.addAll(p.keySet());
        keys.sort();
        String s = keys.get(0)+'='+p.get(keys.get(0));
        for(Integer i=1;i<keys.size();i++) {
            s = s + '&' + keys.get(i)+'='+p.get(keys.get(i));
        }

        return req.getMethod().toUpperCase()+ '&' +
                EncodingUtil.urlEncode(host, 'UTF-8') + '&' +
                EncodingUtil.urlEncode(s, 'UTF-8');
    }

    public void sign(HttpRequest req) {

        nonce = String.valueOf(Crypto.getRandomLong());
        timestamp = String.valueOf(DateTime.now().getTime()/1000);

        refreshParameters();

        String s = createBaseString(parameters, req);System.debug('BASE STRING: ' + s);
        System.debug('Token Secret: '+tokenSecret);
        System.debug('Signature base string: '+s);

        Blob sig = Crypto.generateMac('hmacSHA256', Blob.valueOf(s),
                Blob.valueOf(consumerSecret+'&'+tokenSecret));
        signature = EncodingUtil.urlEncode(EncodingUtil.base64encode(sig), 'UTF-8');

        String header = 'OAuth ';
        for (String key : parameters.keySet()) {
            header = header + key + '="'+parameters.get(key)+'",';
        }
        header = header + 'oauth_signature="'+signature+'"';
        System.debug('Authorization: '+header);
        req.setHeader('Authorization',header);
    }
}
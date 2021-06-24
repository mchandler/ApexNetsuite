@IsTest
public class NetsuiteSigningServiceTest {

    @IsTest
    static void testSign() {
        HttpRequest req = new HttpRequest();
        req.setMethod('GET');
        req.setEndpoint('https://TEST.restlets.api.netsuite.com/app/site/hosting/restlet.nl?script=000&deploy=1');
        req.setHeader('Content-Type','application/json');
        NetsuiteSigningService no = new NetsuiteSigningService('token', 'tokensecret', 'realm', 'consumerKey', 'consumerSecret');
        no.sign(req);

        System.assert(String.isNotBlank(req.getHeader('Authorization')));
    }

}

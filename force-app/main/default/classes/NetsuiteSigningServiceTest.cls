@IsTest
public class NetsuiteSigningServiceTest {

    @IsTest
    static void testSign() {
        HttpRequest req = new HttpRequest();
        req.setMethod('GET');
        req.setEndpoint('https://testing.restlets.api.netsuite.com/app/site/hosting/restlet.nl?script=926&deploy=1');
        req.setHeader('Content-Type','application/json');
        NetsuiteSigningService no = new NetsuiteSigningService();
        no.sign(req);

        System.assert(String.isNotBlank(req.getHeader('Authorization')));
    }

}
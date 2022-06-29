package burp.ScanFun;

import burp.*;

import java.util.List;

public class ShiroScan {

    public static IHttpRequestResponse IsShiro(IHttpRequestResponse baseRequestResponse, IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers){
        IRequestInfo analyzeRequest=helpers.analyzeRequest(baseRequestResponse.getRequest());
        List<String> headers=analyzeRequest.getHeaders();
        byte[] new_Request;
        String headerst= headers.get(headers.size()-1);
        headers.set(headers.size()-1,"Cookie: rememberMe=1");
        headers.add(headerst);
        int bodyOffset = analyzeRequest.getBodyOffset();
        byte[] byte_Request = baseRequestResponse.getRequest();

        String request = new String(byte_Request); //byte[] to String
        String body = request.substring(bodyOffset);
        byte[] byte_body = body.getBytes();  //String to byte[]
        new_Request = helpers.buildHttpMessage(headers, byte_body);

        IHttpRequestResponse requestResponse=callbacks.makeHttpRequest(baseRequestResponse.getHttpService(),new_Request);

        List<String> resheaders=helpers.analyzeResponse(requestResponse.getResponse()).getHeaders();

        for (String reshead:resheaders
             ) {

            if(reshead.contains("rememberMe=deleteMe")){
                return requestResponse;
            }
        }

        return null;
    }
}

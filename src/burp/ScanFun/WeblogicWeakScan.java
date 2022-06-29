package burp.ScanFun;

import burp.Common;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;

import java.util.List;

public class WeblogicWeakScan {

    public static String[] username = {"weblogic", "admin"};
    public static String[] password = {"weblogic", "123456", "111111", "admin"};


    public static IHttpRequestResponse WeblogicBannerPassScan(IHttpRequestResponse reqres, IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) throws InterruptedException {

        List headers = helpers.analyzeRequest(reqres.getRequest()).getHeaders();

        headers.set(0, "POST /bea_wls_deployment_internal/DeploymentService HTTP/1.1");
        byte[] body = helpers.buildHttpMessage(headers, null);
        IHttpRequestResponse weblogicreqres = callbacks.makeHttpRequest(reqres.getHttpService(), body);
        if (weblogicreqres != null && weblogicreqres.getResponse() != null) {
            String res = Common.getResbody(weblogicreqres.getResponse(), helpers);
            if (res.contains("No user name or password") || res.contains("Console/Management")) {
                return weblogicreqres;
            }



        }
        return null;
    }
}



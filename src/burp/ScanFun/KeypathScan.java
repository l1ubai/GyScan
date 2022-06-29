package burp.ScanFun;

import burp.Common;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;

import java.util.List;


public class KeypathScan {

    public static String[] keyPath={"/bea_wls_deployment_internal/DeploymentService","/api/jsonws/invoke"};

    public static IHttpRequestResponse KeypathScan(IHttpRequestResponse reqres, IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers){


        for (String path:keyPath
             ) {
            List headers=helpers.analyzeRequest(reqres.getRequest()).getHeaders();
            if(path.equals("/bea_wls_deployment_internal/DeploymentService"))
            {
                headers.set(0,"POST /bea_wls_deployment_internal/DeploymentService HTTP/1.1");
                byte[] body=helpers.buildHttpMessage(headers,null);
                IHttpRequestResponse weblogicreqres=callbacks.makeHttpRequest(reqres.getHttpService(),body);
                if(weblogicreqres!=null && weblogicreqres.getResponse()!=null)
                {
                    String res= Common.getResbody(weblogicreqres.getResponse(),helpers);
                    if(res.contains("No user name or password"))
                    {

                    }

                }
            }



        }

        return null;
    }

}

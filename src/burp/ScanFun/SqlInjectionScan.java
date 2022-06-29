package burp.ScanFun;

import burp.*;
import burp.Listen.Ceye;
import org.checkerframework.checker.units.qual.C;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class SqlInjectionScan {

    public static List<String> pocs = new ArrayList<String>();
    private static final byte[] Succ_1 = "You have an error".getBytes();
    private static final byte[] Succ_2 = "SQl".getBytes();
    private static final byte[] Succ_3 = "systemProperties".getBytes();


    public static IHttpRequestResponse ScanSqlInjectionParam(IHttpRequestResponse baseRequestResponse, IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) throws UnsupportedEncodingException {
        if (baseRequestResponse.getRequest() != null) {
            //pocs.add("'");
            List<String> headers = helpers.analyzeRequest(baseRequestResponse).getHeaders();
            String reqMethod = helpers.analyzeRequest(baseRequestResponse).getMethod();
            byte[] originres = baseRequestResponse.getResponse();
            //List<String> pocs = GenPoc.GenLog4Poc(host);
            //BurpExtender.stdout.println(newhost);
            //对消息体进行解析,messageInfo是整个HTTP请求和响应消息体的总和，各种HTTP相关信息的获取都来自于它，HTTP流量的修改都是围绕它进行的。

            /*****************获取参数**********************/
            if (reqMethod.equalsIgnoreCase("get")) {

                String poc="'";
                    headers = helpers.analyzeRequest(baseRequestResponse).getHeaders();
                    List<String> targetList = Common.ParamAddPocGetNoreplace(headers.get(0), poc);
                    for (int i=0;i<targetList.size();i++) {
                        //BurpExtender.stdout.println(targetList.size());
                        headers.set(0, targetList.get(i));
                        byte[] body = helpers.buildHttpMessage(headers, null);
                        IHttpRequestResponse requestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), body);
                        if (requestResponse != null && requestResponse.getResponse() != null) {
                            if (makeSure(originres, requestResponse.getResponse(), helpers).equals("100")) {
                                return requestResponse;
                            }

                            if (makeSure(originres, requestResponse.getResponse(), helpers).equals("code not")) {
                                List<String> targetListbihe = Common.ParamAddPocGetNoreplace(headers.get(0), "'");
                                headers.set(0, targetListbihe.get(i));
                                byte[] bodybihe = helpers.buildHttpMessage(headers, null);
                                IHttpRequestResponse requestResponsebihe = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), bodybihe);
                                if (helpers.analyzeResponse(originres).getStatusCode() == helpers.analyzeResponse(requestResponsebihe.getResponse()).getStatusCode()) {
                                    return requestResponsebihe;
                                }

                            }
                        }
                    }



            }
            if (reqMethod.equalsIgnoreCase("post")) {
                //BurpExtender.stdout.println("是post");
                headers = helpers.analyzeRequest(baseRequestResponse).getHeaders();
                boolean json = false;
                boolean multipart = true;
                String Contenttype = Byte.toString(helpers.analyzeRequest(baseRequestResponse).getContentType());
                //BurpExtender.stdout.println(Contenttype);
                for (String header : headers
                ) {
                    if (header.contains("Content-Type: json/application") || header.contains("Content-Type: application/json")) {
                        json = true;
                    }
                    if (header.contains("multipart/form-data")) {
                        multipart = false;
                    }
                }


                if (!json && multipart) {

                    int start = helpers.analyzeRequest(baseRequestResponse.getRequest()).getBodyOffset();
                    byte[] srcbody = baseRequestResponse.getRequest();
                    byte[] reqbody = Common.getpostParams(start, srcbody);

                    String reqbodystr = new String(Common.getpostParams(start, srcbody), "utf-8");
                    //BurpExtender.stdout.println(reqbodystr);

                    String poc="'";
                        List<String> targertList = Common.ParamAddPocPostNoreplace(reqbodystr, poc);
                        for (int i = 0; i < targertList.size(); i++) {

                            byte[] body = helpers.buildHttpMessage(headers, targertList.get(i).getBytes(StandardCharsets.UTF_8));
                            IHttpRequestResponse requestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), body);
                            if (requestResponse != null && requestResponse.getResponse() != null) {
                                if (makeSure(originres, requestResponse.getResponse(), helpers).equals("100")) {
                                    return requestResponse;
                                }
                                if (makeSure(originres, requestResponse.getResponse(), helpers).equals("code")) {
                                    List<String> targertListbihe = Common.ParamAddPocPostNoreplace(reqbodystr, "''");
                                    body = helpers.buildHttpMessage(headers, targertListbihe.get(i).getBytes(StandardCharsets.UTF_8));
                                    IHttpRequestResponse requestResponsebihe = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), body);
                                    if (makeSure(originres, requestResponsebihe.getResponse(), helpers).equals("body")) {
                                        return requestResponsebihe;
                                    }

                                }
                                if (makeSure(originres, requestResponse.getResponse(), helpers).equals("code not")) {
                                    List<String> targertListbihe = Common.ParamAddPocPostNoreplace(reqbodystr, "''");
                                    body = helpers.buildHttpMessage(headers, targertListbihe.get(i).getBytes(StandardCharsets.UTF_8));
                                    IHttpRequestResponse requestResponsebihe = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), body);
                                    if (helpers.analyzeResponse(originres).getStatusCode() == helpers.analyzeResponse(requestResponsebihe.getResponse()).getStatusCode()) {
                                        return requestResponsebihe;
                                    }

                                }
                            }

                        }

                }
                if (json && multipart) {
                    //BurpExtender.stdout.println("是json");
                    int start = helpers.analyzeRequest(baseRequestResponse.getRequest()).getBodyOffset();
                    byte[] srcbody = baseRequestResponse.getRequest();
                    byte[] reqbody = Common.getpostParams(start, srcbody);

                    String reqbodystr = new String(Common.getpostParams(start, srcbody), "utf-8");
                    String poc="'";
                        List<String> targetList = Common.ParamAddPocPostJsonNoreplace(reqbodystr, poc);

                        for (int i=0;i<targetList.size();i++) {
                            byte[] body = helpers.buildHttpMessage(headers, targetList.get(i).getBytes(StandardCharsets.UTF_8));
                            IHttpRequestResponse requestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), body);
                            if (requestResponse != null && requestResponse.getResponse() != null) {
                                if (makeSure(originres, requestResponse.getResponse(), helpers).equals("100")) {
                                    return requestResponse;
                                }
//                                if (makeSure(originres, requestResponse.getResponse(), helpers).equals("code")) {
//                                    List<String> targertListbihe = Common.ParamAddPocPostJsonNoreplace(reqbodystr, "''");
//                                    body = helpers.buildHttpMessage(headers, targertListbihe.get(i).getBytes(StandardCharsets.UTF_8));
//                                    IHttpRequestResponse requestResponsebihe = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), body);
//                                    if (makeSure(originres, requestResponsebihe.getResponse(), helpers).equals("body")) {
//                                        return requestResponsebihe;
//                                    }
//
//                                }
                                if (makeSure(originres, requestResponse.getResponse(), helpers).equals("code not")) {
                                    List<String> targertListbihe = Common.ParamAddPocPostJsonNoreplace(reqbodystr, "''");
                                    body = helpers.buildHttpMessage(headers, targertListbihe.get(i).getBytes(StandardCharsets.UTF_8));
                                    IHttpRequestResponse requestResponsebihe = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), body);
                                    if (helpers.analyzeResponse(originres).getStatusCode() == helpers.analyzeResponse(requestResponsebihe.getResponse()).getStatusCode()) {
                                        return requestResponsebihe;
                                    }

                                }
                            }
                        }
                        //BurpExtender.stdout.println(reqbodystr);

                }

            }
        }

        return null;
    }


    public static String makeSure(byte[] originRes, byte[] newRes, IExtensionHelpers helpers) {

        Integer origincode = (int) helpers.analyzeResponse(originRes).getStatusCode();
        Integer newcode = (int)  helpers.analyzeResponse(newRes).getStatusCode();

        //BurpExtender.stdout.println("origincode"+origincode);
        //BurpExtender.stdout.println("onewcode"+newcode);
        String originbody = Common.getResbody(originRes, helpers);
        String newbody = Common.getResbody(newRes, helpers);
        if (newbody.toLowerCase(Locale.ROOT).contains("sql") || newbody.toLowerCase(Locale.ROOT).contains("You have an error in")) {
            return "100";
        }

//        if (origincode.equals(newcode)) {
//            //BurpExtender.stdout.println("两个相等，进入了这里");
//            if (newbody.length() - originbody.length() >= 15 || newbody.length() - originbody.length() <= -15) {
//                return "code";
//            }
//            if(newbody.length() == originbody.length()) {
//
//                return "body";
//            }
//        }

        if(!origincode.equals(newcode)){
            //BurpExtender.stdout.println("两个不啊啊啊啊相等，进入了这里");
            return "code not";
        }

    return "null";
    }
}


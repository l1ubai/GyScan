package burp;

import java.io.PrintWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;


public class BurpExtender implements IBurpExtender, IScannerCheck {
    static PrintWriter stdout;
    static PrintWriter stderr;
    static IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private String ExtenderName = "SpringActuator Unauthorized";
    private static final byte[] Succ_env_v1 = "/env".getBytes();
    private static final byte[] Succ_refresh_v1 = "/heapdump".getBytes();
    private static final byte[] Succ_env_v2 = "actuator/env".getBytes();
    private static final byte[] Succ_refresh_v2 = "actuator/heapdump".getBytes();
    private static final String[] poc_v1 = {"env", "mappings", "gateway"};
    private static final String[] poc_v2 = {"actuator/", "actuator/env"};
    private static final byte[] Succ_env = "systemProperties".getBytes();
    private static final String[] poc_jiekou = {"swagger-ui.html", "druid/", "v2/api-docs"};
    List<IScanIssue> issues = new ArrayList(1);

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);
        callbacks.printOutput(ExtenderName);
        //stdout.println(ExtenderName);
        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();
        this.stdout.println("===========================");
        this.stdout.println("[+]   load successful!     ");
        this.stdout.println("[+]SpringActuator Unauthorized");
        this.stdout.println("[+]   code by zzzz v1.1     ");
        this.stdout.println("===========================");
        callbacks.setExtensionName(ExtenderName);
        callbacks.registerContextMenuFactory(new Menu(this));
        callbacks.registerScannerCheck(this);

    }


    public void doScan(IHttpRequestResponse baseRequestResponse) {
        URL url = this.helpers.analyzeRequest(baseRequestResponse).getUrl();
        List headers = this.helpers.analyzeRequest(baseRequestResponse).getHeaders();
        //获取遍历路径
        List queue = MakeCrossQueue((String) headers.get(0));


        for (int j = 0; j < queue.size(); j++) {
            String path = (String) queue.get(j);
            //v2检测
            for (int i = 0; i < poc_v2.length; i++) {
                String fpath = AddPoc(path, poc_v2[i]);
                headers.set(0, fpath);
                byte[] body = this.helpers.buildHttpMessage(headers, null);
                int a = (int) ((Math.random() * 9.0 + 1.0) * 100000.0);
                // headers.add("Testecho:" + a);
                try {
                    IHttpRequestResponse requestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), body);
                    if (requestResponse != null && requestResponse.getResponse() != null) {
                        byte[] response = requestResponse.getResponse();
                        IResponseInfo responseInfo = this.helpers.analyzeResponse(response);
                        List respHeaders = responseInfo.getHeaders();
                        List<int[]> matches_v2 = getMatches(requestResponse.getResponse(), Succ_env_v2);
                        if (matches_v2.size() > 0) {
                            List<int[]> matches_v2_2 = getMatches(requestResponse.getResponse(), Succ_refresh_v2);
                            if (matches_v2_2.size() > 0) {
                                stdout.println("mingzhong");
//                            List issues = new ArrayList(1);
//                            issues.add(new CustomScanIssue(requestResponse.getHttpService(), url, new IHttpRequestResponse[]{baseRequestResponse}, "111", "1", "High"));
                                callbacks.addScanIssue(new CustomScanIssue(requestResponse.getHttpService(), url, new IHttpRequestResponse[]{requestResponse}, "Spring Actuator Unauthorized (..;) ", "version :v2  path: " + fpath, "High"));
                            }
                        }
                        //根据env中systemProperties的来判断是否成功
                        List<int[]> matches_v3 = getMatches(requestResponse.getResponse(), Succ_env);
                        {
                            if (matches_v3.size() > 0) {
                                stdout.println("mingzhong");
//                            List issues = new ArrayList(1);
//                            issues.add(new CustomScanIssue(requestResponse.getHttpService(), url, new IHttpRequestResponse[]{baseRequestResponse}, "111", "1", "High"));
                                callbacks.addScanIssue(new CustomScanIssue(requestResponse.getHttpService(), url, new IHttpRequestResponse[]{requestResponse}, "Spring Actuator Unauthorized (..;) ", "version :v2  path: " + fpath, "High"));
                            }
                        }
                    }
                } catch (Exception var21) {
                    stdout.println(var21.getMessage());
                }
            }
            //v1检测
            for (int i = 0; i < poc_v1.length; i++) {
                String fpath = AddPoc(path, poc_v1[i]);
                headers.set(0, fpath);
                byte[] body = this.helpers.buildHttpMessage(headers, null);
                int a = (int) ((Math.random() * 9.0 + 1.0) * 100000.0);
                // headers.add("Testecho:" + a);
                try {
                    IHttpRequestResponse requestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), body);
                    if (requestResponse != null && requestResponse.getResponse() != null) {
                        byte[] response = requestResponse.getResponse();
                        IResponseInfo responseInfo = this.helpers.analyzeResponse(response);
                        List respHeaders = responseInfo.getHeaders();
                        List<int[]> matches_v1 = getMatches(requestResponse.getResponse(), Succ_env_v1);
                        if (matches_v1.size() > 0) {
                            List<int[]> matches_v1_2 = getMatches(requestResponse.getResponse(), Succ_refresh_v1);
                            if (matches_v1_2.size() > 0) {
                                stdout.println("mingzhong");
//                            List issues = new ArrayList(1);
//                            issues.add(new CustomScanIssue(requestResponse.getHttpService(), url, new IHttpRequestResponse[]{baseRequestResponse}, "111", "1", "High"));
                                callbacks.addScanIssue(new CustomScanIssue(requestResponse.getHttpService(), url, new IHttpRequestResponse[]{requestResponse}, "Spring Actuator Unauthorized (..;) ", "version :v1 \n path: " + fpath, "High"));
                            }
                        }
                        //根据env中systemProperties的来判断是否成功
                        List<int[]> matches_v3 = getMatches(requestResponse.getResponse(), Succ_env);
                        {
                            if (matches_v3.size() > 0) {
                                stdout.println("mingzhong");
//                            List issues = new ArrayList(1);
//                            issues.add(new CustomScanIssue(requestResponse.getHttpService(), url, new IHttpRequestResponse[]{baseRequestResponse}, "111", "1", "High"));
                                callbacks.addScanIssue(new CustomScanIssue(requestResponse.getHttpService(), url, new IHttpRequestResponse[]{requestResponse}, "Spring Actuator Unauthorized (..;) ", "version :v1  path: " + fpath, "High"));
                            }
                        }
                    }
                } catch (Exception var21) {
                    stdout.println(var21.getMessage());
                }
            }
        }

    }


    private List<int[]> getMatches(byte[] response, byte[] match) {
        List<int[]> matches = new ArrayList<int[]>();

        int start = 0;
        while (start < response.length) {
            start = helpers.indexOf(response, match, true, start, response.length);
            if (start == -1)
                break;
            matches.add(new int[]{start, start + match.length});
            start += match.length;
        }

        return matches;
    }

    public static List<String> MakeQueue(String header){
        List queue =new ArrayList();
        String test="";
        String[] headers=header.split("/");
        int i=0;
        System.out.printf(String.valueOf(headers.length));
        String poc="env";
        int count=headers.length-3;
        int begin=headers.length-2;
        for(i=begin;i>=begin-count;i--)
        {   String fianlheader="";
            for(int j=0;j<i;j++)
            {
                fianlheader=fianlheader+headers[j]+"/";

            }
            fianlheader=fianlheader+" HTTP/"+headers[headers.length-1];
            fianlheader=fianlheader.replace("POST ","GET ");
            fianlheader=fianlheader.replace("OPTIONS ","GET ");
            fianlheader=fianlheader.replace("PUT ","GET ");
            fianlheader=fianlheader.replace("DELETE ","GET ");
            queue.add(fianlheader);
            //System.out.println(fianlheader);
        }
        return queue;
    }
    public static List<String> MakeCrossQueue(String header) {
        List queue = new ArrayList();
        String test = "";
        String[] headers = header.split("/");
        int i = 0;
        String forigin="";
        for (int o=0;o<headers.length-1;o++)
        {   if(o==headers.length-2)
        {
            forigin += headers[o].split(" ")[0] + "/";
        }
        else {
            forigin += headers[o] + "/";
        }
        }
        for (i = 0; i < headers.length - 1; i++) {
            String fianlheader = "";
            forigin = forigin + "..;/";
            fianlheader = forigin + " HTTP/" + headers[headers.length - 1];
            fianlheader=fianlheader.replace("POST ","GET ");
            fianlheader=fianlheader.replace("OPTIONS ","GET ");
            fianlheader=fianlheader.replace("PUT ","GET ");
            fianlheader=fianlheader.replace("DELETE ","GET ");
            queue.add(fianlheader);
            //System.out.println(fianlheader);
        }
        return queue;
    }

    public static String AddPoc(String path, String poc) {
        String fpath = "";
        String[] paths = path.split("/");
        for (int i = 0; i < paths.length; i++) {

            if (i == paths.length - 1) {
                fpath += paths[i];
            } else if (i == paths.length - 2) {
                fpath += poc + " HTTP/";
            } else {
                fpath += paths[i] + "/";
            }

        }
        return fpath;

    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        if (IsneedScan(baseRequestResponse)) {
            URL url = this.helpers.analyzeRequest(baseRequestResponse).getUrl();
            String reqMethod = this.helpers.analyzeRequest(baseRequestResponse).getMethod();
            List headers = this.helpers.analyzeRequest(baseRequestResponse).getHeaders();
            //获取遍历路径
            List queue = MakeQueue((String) headers.get(0));
            //stdout.println(queue.get(0));
            for (int j = 0; j < queue.size(); j++) {
                String path = (String) queue.get(j);
                //v2检测
                for (int i = 0; i < poc_v2.length; i++) {
                    String fpath = AddPoc(path, poc_v2[i]);
                    headers.set(0, fpath);
                    byte[] body = this.helpers.buildHttpMessage(headers, null);
                    int a = (int) ((Math.random() * 9.0 + 1.0) * 100000.0);
                    // headers.add("Testecho:" + a);
                    try {
                        IHttpRequestResponse requestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), body);
                        if (requestResponse != null && requestResponse.getResponse() != null) {
                            byte[] response = requestResponse.getResponse();
                            IResponseInfo responseInfo = this.helpers.analyzeResponse(response);

                            List<int[]> matches_v2 = getMatches(requestResponse.getResponse(), Succ_env_v2);
                            if (matches_v2.size() > 0) {
                                List<int[]> matches_v2_2 = getMatches(requestResponse.getResponse(), Succ_refresh_v2);
                                if (matches_v2_2.size() > 0) {
                                    stdout.println("mingzhong");
                                    IScanIssue newissuse = new CustomScanIssue(requestResponse.getHttpService(), url, new IHttpRequestResponse[]{requestResponse}, "Spring Actuator Unauthorized", "version :v2 \n path: " + fpath, "High");
                                    int judge;
                                    boolean add = true;
                                    for (int count = 0; count < issues.size(); count++) {
                                        judge = consolidateDuplicateIssues(issues.get(0), newissuse);
                                        if (judge == 0) {
                                            add = false;
                                            //    callbacks.addScanIssue(new CustomScanIssue(requestResponse.getHttpService(), url, new IHttpRequestResponse[]{requestResponse}, "Spring Actuator Unauthorized", "version :v1 \n path: " + fpath, "High"));
                                        }
                                    }
                                    if (add) {
                                        issues.add(new CustomScanIssue(requestResponse.getHttpService(), url, new IHttpRequestResponse[]{requestResponse}, "Spring Actuator Unauthorized", "version :v2 \n path: " + fpath, "High"));
                                        return issues;
                                    }
                                }


                            }
                            //根据env中systemProperties的来判断是否成功
                            List<int[]> matches_v3 = getMatches(requestResponse.getResponse(), Succ_env);

                            if (matches_v3.size() > 0) {
                                stdout.println("mingzhong");
                                IScanIssue newissuse = new CustomScanIssue(requestResponse.getHttpService(), url, new IHttpRequestResponse[]{requestResponse}, "Spring Actuator Unauthorized", "version :v2 \n path: " + fpath, "High");
                                int judge;
                                boolean add = true;
                                for (int count = 0; count < issues.size(); count++) {
                                    judge = consolidateDuplicateIssues(issues.get(0), newissuse);
                                    if (judge == 0) {
                                        add = false;
                                        //    callbacks.addScanIssue(new CustomScanIssue(requestResponse.getHttpService(), url, new IHttpRequestResponse[]{requestResponse}, "Spring Actuator Unauthorized", "version :v1 \n path: " + fpath, "High"));
                                    }
                                }
                                if (add) {
                                    issues.add(new CustomScanIssue(requestResponse.getHttpService(), url, new IHttpRequestResponse[]{requestResponse}, "Spring Actuator Unauthorized", "version :v2 \n path: " + fpath, "High"));
                                    return issues;
                                }
                            }
                        }
                    } catch (Exception var21) {
                        stdout.println(var21.getMessage());
                    }

                }
                //v1检测
                for (int i = 0; i < poc_v1.length; i++) {
                    String fpath = AddPoc(path, poc_v1[i]);
                    headers.set(0, fpath);
                    byte[] body = this.helpers.buildHttpMessage(headers, null);
                    int a = (int) ((Math.random() * 9.0 + 1.0) * 100000.0);
                    // headers.add("Testecho:" + a);
                    try {
                        IHttpRequestResponse requestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), body);
                        if (requestResponse != null && requestResponse.getResponse() != null) {
                            byte[] response = requestResponse.getResponse();
                            IResponseInfo responseInfo = this.helpers.analyzeResponse(response);
                            List respHeaders = responseInfo.getHeaders();
                            List<int[]> matches_v1 = getMatches(requestResponse.getResponse(), Succ_env_v1);
                            if (matches_v1.size() > 0) {
                                List<int[]> matches_v1_2 = getMatches(requestResponse.getResponse(), Succ_refresh_v1);

                                if (matches_v1_2.size() > 0) {

                                    stdout.println("mingzhong");
                                    IScanIssue newissuse = new CustomScanIssue(requestResponse.getHttpService(), url, new IHttpRequestResponse[]{requestResponse}, "Spring Actuator Unauthorized", "version :v1 \n path: " + fpath, "High");
                                    int judge;
                                    boolean add = true;
                                    for (int count = 0; count < issues.size(); count++) {
                                        judge = consolidateDuplicateIssues(issues.get(0), newissuse);
                                        if (judge == 0) {
                                            add = false;
                                            //    callbacks.addScanIssue(new CustomScanIssue(requestResponse.getHttpService(), url, new IHttpRequestResponse[]{requestResponse}, "Spring Actuator Unauthorized", "version :v1 \n path: " + fpath, "High"));
                                        }
                                    }
                                    if (add) {
                                        issues.add(new CustomScanIssue(requestResponse.getHttpService(), url, new IHttpRequestResponse[]{requestResponse}, "Spring Actuator Unauthorized", "version :v1 \n path: " + fpath, "High"));
                                        return issues;
                                    }


                                }
                            }
                            //根据env中systemProperties的来判断是否成功
                            List<int[]> matches_v3 = getMatches(requestResponse.getResponse(), Succ_env);

                            if (matches_v3.size() > 0) {
                                stdout.println("mingzhong");
                                IScanIssue newissuse = new CustomScanIssue(requestResponse.getHttpService(), url, new IHttpRequestResponse[]{requestResponse}, "Spring Actuator Unauthorized", "version :v2 \n path: " + fpath, "High");
                                int judge;
                                boolean add = true;
                                for (int count = 0; count < issues.size(); count++) {
                                    judge = consolidateDuplicateIssues(issues.get(0), newissuse);
                                    if (judge == 0) {
                                        add = false;
                                        //    callbacks.addScanIssue(new CustomScanIssue(requestResponse.getHttpService(), url, new IHttpRequestResponse[]{requestResponse}, "Spring Actuator Unauthorized", "version :v1 \n path: " + fpath, "High"));
                                    }
                                }
                                if (add) {
                                    issues.add(new CustomScanIssue(requestResponse.getHttpService(), url, new IHttpRequestResponse[]{requestResponse}, "Spring Actuator Unauthorized", "version :v2 \n path: " + fpath, "High"));
                                    return issues;
                                }
                            }
                        }
                    } catch (Exception var21) {
                        stdout.println(var21.getMessage());
                    }
                }
            }

        }
        return null;
    }


    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {

        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        stdout.println(existingIssue.getHttpService().getHost());
        stdout.println(newIssue.getHttpService().getHost());
        return existingIssue.getHttpService().getHost().equals(newIssue.getHttpService().getHost()) ? 0 : 1;
    }

    public boolean IsneedScan(IHttpRequestResponse baseRequestResponse) {
        for (int count = 0; count < issues.size(); count++) {
            if (issues.get(count).getHttpService().getHost() == baseRequestResponse.getHttpService().getHost()) {
                return false;
            }
        }

        return true;
    }
}



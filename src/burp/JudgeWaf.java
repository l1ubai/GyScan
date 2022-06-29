package burp;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class JudgeWaf {

    private static final String poc_cross = "..;";
    private static final String poc_usually = "etc/passwd";
    private static final byte[] Waf_1 = "防火墙".getBytes();
    private static final byte[] Waf_2 = "拦截".getBytes();
    //SafeLine 403


            public  static Map ReturnLevel(IHttpRequestResponse baseRequestResponse,IExtensionHelpers helpers,IBurpExtenderCallbacks callbacks)

            {   Map<String, Short> level=new HashMap<String, Short>();
                level.put("cross", (short) 1);
                level.put("uspath", (short) 1);
                List headers = helpers.analyzeRequest(baseRequestResponse).getHeaders();
                Short OriginStatus=helpers.analyzeResponse(baseRequestResponse.getResponse()).getStatusCode();
                String path=AddPoc((String) headers.get(0),poc_cross);
                //cross
                headers.set(0,path);
                byte[] body=helpers.buildHttpMessage(headers,null);
                IHttpRequestResponse requestResponse=callbacks.makeHttpRequest(baseRequestResponse.getHttpService(),body);

                if (requestResponse != null && requestResponse.getResponse() != null) {

                    if (helpers.analyzeResponse(requestResponse.getResponse()).getStatusCode() != OriginStatus) {

                        List<int[]> matches = getMatches(requestResponse.getResponse(), Waf_1, helpers);
                        if (matches.size() > 0) {
                            level.replace("cross", (short) 0);
                        }
                        matches = getMatches(requestResponse.getResponse(), Waf_2, helpers);
                        if (matches.size() > 0) {
                            level.replace("cross", (short) 0);
                        }
                    }
                    if (helpers.analyzeResponse(requestResponse.getResponse()).getStatusCode() == 0) {
                        level.replace("cross", (short) 0);
                    }
                }

                else{
                    level.replace("cross", (short) 0);
                }

                //uspath
                headers = helpers.analyzeRequest(baseRequestResponse).getHeaders();
                OriginStatus=helpers.analyzeResponse(baseRequestResponse.getResponse()).getStatusCode();
                path=AddPoc((String) headers.get(0),poc_usually);
                headers.set(0,path);
                body=helpers.buildHttpMessage(headers,null);
                requestResponse=callbacks.makeHttpRequest(baseRequestResponse.getHttpService(),body);

                if (requestResponse != null && requestResponse.getResponse() != null) {

                    if (helpers.analyzeResponse(requestResponse.getResponse()).getStatusCode() != OriginStatus) {

                        List<int[]> matches = getMatches(requestResponse.getResponse(), Waf_1, helpers);
                        if (matches.size() > 0) {
                            level.replace("uspath", (short) 0);
                        }
                        matches = getMatches(requestResponse.getResponse(), Waf_2, helpers);
                        if (matches.size() > 0) {
                            level.replace("uspath", (short) 0);
                        }
                    }
                    if (helpers.analyzeResponse(requestResponse.getResponse()).getStatusCode() == 0) {
                        level.replace("uspath", (short) 0);
                    }
                }

                else{
                    level.replace("uspath", (short) 0);
                }


                return level;

        }


    public static List<int[]> getMatches(byte[] response, byte[] match, IExtensionHelpers helpers) {
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



    public static String AddPoc(String path,String poc)
    {
        String fpath="";
        String[] paths=path.split("/");
        for(int i=0;i<paths.length;i++) {

            if(i== paths.length-1)
            {
                fpath+=paths[i];
            }
            else if(i==paths.length-2)
            {
                fpath+=poc+" HTTP/";
            }
            else {
                fpath+=paths[i] + "/";
            }

        }
        return fpath;

    }
}

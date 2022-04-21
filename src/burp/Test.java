package burp;

import java.util.ArrayList;
import java.util.List;

public class Test {


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
            fianlheader=fianlheader.replace("OPSTIONS ","GET ");
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
            fianlheader=fianlheader.replace("OPSTIONS ","GET ");
            fianlheader=fianlheader.replace("PUT ","GET ");
            fianlheader=fianlheader.replace("DELETE ","GET ");
            queue.add(fianlheader);
            //System.out.println(fianlheader);
        }
        return queue;
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
    public static void main(String[] args) {
        String header="POST /dwadwa/fwafwafwa HTTP/1.1";
        List<String> sss=MakeCrossQueue(header);
        for(int i=0;i<sss.size();i++)
        {
            System.out.println(sss.get(i));
        }
        String fpath=AddPoc(header,"1");
        System.out.printf(fpath);
    }
}

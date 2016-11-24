#
# (C) Tenable Network Security, Inc.
#
# @@NOTE: The output of this plugin should not be changed
#
 

if (description)
{
  script_version("$Revision: 2.10 $");
  script_id(11936);

  name["english"] = "OS Identification";
  script_name(english:name["english"]);

  desc["english"] = "
This script attempts to identify the Operating System type and version by
looking at the results of other scripts";

  script_description(english:desc["english"]);
 
  summary["english"] = "Determines the remote operating system";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
  family["english"] = "General";
  script_family(english:family["english"]);
  script_dependencies("os_fingerprint_http.nasl",
		      "os_fingerprint_html.nasl",
		      "os_fingerprint_mdns.nasl",
		      "os_fingerprint_ntp.nasl",
		      "os_fingerprint_sinfp.nasl",
		      "os_fingerprint_smb.nasl",
		      "os_fingerprint_snmp.nasl",
		      "os_fingerprint_ftp.nasl",
		      "os_fingerprint_xprobe.nasl",
		      "os_fingerprint_msrprc.nasl",
		      "os_fingerprint_uname.nasl",
		      "os_fingerprint_ssh.nasl",
		      "os_fingerprint_linux_distro.nasl",
		      "os_fingerprint_telnet.nasl");
  if ( NASL_LEVEL >= 3000 )
	script_dependencies("os_fingerprint_rdp.nbin");
  exit(0);
}



methods = make_list("HTTP", "HTML", "mDNS", "NTP", "SinFP", "SMB", "SNMP", "ICMP", "uname", "RDP", "MSRPC", "SSH", "LinuxDistribution", "telnet", "FTP");

function get_best_match()
{
 local_var meth;
 local_var best_match;
 local_var best_score;
 local_var best_type;
 local_var best_meth;
 local_var best_meth1;
 local_var kb;
 local_var score;
 local_var ret;
 local_var len, len2;

 foreach meth (methods) 
 {
  kb = get_kb_item("Host/OS/" + meth);
  if( kb )
  {
   score = get_kb_item("Host/OS/" + meth + "/Confidence");
   if ( score < best_score ) continue;
   best_score = score;
   best_meth  = meth;
   best_match  = kb;
   best_type  = get_kb_item("Host/OS/" + meth + "/Type"); 
  } 
 }

 if (isnull(best_meth))  return NULL;

 # Try to find something more precise
 best_meth1 = best_meth;
 len = strlen(best_match);
 foreach meth (methods) 
   if (meth != best_meth)
   {
     kb = get_kb_item("Host/OS/" + meth);
     len2 = strlen(kb);
     if(len2 > len && best_match >< kb && '\n' >!< kb)
     {
       len = len2;
       score = get_kb_item("Host/OS/" + meth + "/Confidence");
       # best_score = score;
       best_meth  = meth;
       best_match  = kb;
       best_type  = get_kb_item("Host/OS/" + meth + "/Type"); 
     } 
   }

  ret["meth"] = best_meth;
  if (best_meth != best_meth1) ret["meth1"] = best_meth1;
  ret["confidence"] = best_score;
  ret["os"] = best_match;
  ret["type"] = best_type;
  return ret;
}

function get_fingerprint()
{
 local_var meth;
 local_var ret;
 local_var kb;

 foreach meth ( methods )
 {
  kb = get_kb_item("Host/OS/" + meth + "/Fingerprint");
  if ( kb )
  {
    if ( get_kb_item("Host/OS/" + meth) )
     ret += meth + ':' + kb + '\n';
    else	
     ret += meth + ':!:' + kb + '\n';
  }
 }
 return ret;
}

function missing_fingerprints()
{
 local_var meth;
 local_var flag;
  
 flag = 0;
 foreach meth ( methods )
 {
  if ( meth == "HTTP" || meth == "ICMP"  || meth == "SSH" || meth == "telnet" ) continue;
  if ( get_kb_item("Host/OS/" + meth + "/Fingerprint") &&
      !get_kb_item("Host/OS/" + meth) )  flag ++;
 }

 if ( flag ) return 1;
 else return 0;
}



ret = get_best_match();

if ( ! isnull(ret) )
{
 report = '\nRemote operating system : ' + ret["os"];
 report += '\nConfidence Level : ' + ret["confidence"];
 report += '\nMethod : ' + ret["meth"] + '\n';
 if (ret["meth1"])
 report += '\nPrimary Method : ' + ret["meth1"] + '\n';
 
 if ( missing_fingerprints() )
 {
  fg = get_fingerprint();
  if ( fg ) report += '\nNot all fingerprints could give a match - please email the following to os-signatures@nessus.org :\n' + fg;
 }
 
 if ( '\n' >!< ret["os"] )
  report += '\n \nThe remote host is running ' + ret["os"];
 else
  report += '\n \nThe remote host is running one of these operating systems : \n' + ret["os"];

 if ( defined_func("report_xml_tag") )
  report_xml_tag(tag:"operating-system", value:ret["os"]);

 security_note(port:0, data:report); 
 if ( !isnull(ret["os"]) ) set_kb_item(name:"Host/OS", value:ret["os"]);
 if ( !isnull(ret["confidence"]) ) set_kb_item(name:"Host/OS/Confidence", value:ret["confidence"]);
 if ( ! isnull(ret["type"]) ) set_kb_item(name:"Host/OS/Type", value:ret["type"]);
 
 exit(0);
}
else
{
 fg = get_fingerprint();
 if ( fg ) 
 {
 report += 
'The remote host operating system could not be identified. If you know what operating
system is installed on the remote host , please send this signature and the name and 
version of the remote operating system to os-signatures@nessus.org :\n' + fg;
 }
}


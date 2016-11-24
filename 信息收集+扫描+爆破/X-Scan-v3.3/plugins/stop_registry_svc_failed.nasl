#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(35706);
 script_version ("$Revision: 1.1 $");
 
 name["english"] = "SMB Registry : Stopping the Registry Service after the scan failed";
 script_name(english:name["english"]);
 
  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The registry service could not be stopped after the scan."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
	"To perform a full credentialed scan, Nessus needs the ability to connect to\n",
	"the remote registry service (RemoteRegistry).\n",
        "\n",
	"While Nessus successfully started the registry service, it could not stop it\n",
	"after the scan. You might want to disable it manually.\n"
    )
  );
  script_set_attribute(
    attribute:"risk_factor", 
    value:"None"
  );
  script_end_attributes();

 
 summary["english"] = "Determines whether the remote registry service was stopped by nessusd";
 script_summary(english:summary["english"]);
 
 script_category(ACT_END);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc");
 family["english"] = "Settings";
 script_family(english:family["english"]);
 
 script_dependencies("stop_registry_svc.nasl");
 script_require_keys("SMB/stop_registry/failed");
 exit(0);
}


err = get_kb_item("SMB/stop_registry/failed");
if ( err ) security_note(port:0, extra:'\nThe following error occured :\n\n' + err);

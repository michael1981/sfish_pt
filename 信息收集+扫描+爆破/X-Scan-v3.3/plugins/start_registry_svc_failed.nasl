#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(35705);
 script_version ("$Revision: 1.1 $");
 
 name["english"] = "SMB Registry : Starting the Registry Service during the scan failed";
 script_name(english:name["english"]);
 
  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The registry service could not be enabled for the duration of the scan."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
	"To perform a full credentialed scan, Nessus needs the ability to connect to\n",
	"the remote registry service (RemoteRegistry).\n\n",
	"Nessus attempted to start the service but failed, therefore some local checks\n",
	"will not be performed against the remote host."
    )
  );
  script_set_attribute(
    attribute:"risk_factor", 
    value:"None"
  );
  script_end_attributes();

 
 
 summary["english"] = "Determines whether the remote registry service is running";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc");
 family["english"] = "Settings";
 script_family(english:family["english"]);
 
 script_dependencies("start_registry_svc.nasl");
 script_require_keys("SMB/start_registry/failed");
 exit(0);
}

err = get_kb_item("SMB/start_registry/failed");
if ( err ) security_note(port:0, extra:'\nThe following error occurred :\n\n'+err);

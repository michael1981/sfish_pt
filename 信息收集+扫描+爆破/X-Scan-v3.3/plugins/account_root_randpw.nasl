#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40987);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2009-3232");
  script_bugtraq_id(36306);
  script_xref(name:"OSVDB", value:"57908");
  script_xref(name:"Secunia", value:"36620");

  script_name(english:"Random password for 'root' account");
  script_summary(english:"Tries to SSH as root with a random password");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote system has an authentication bypass vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "Nessus was able to login to the remote host as 'root' via SSH with a\n",
      "random password.\n",
      "\n",
      "A remote attacker can exploit this to gain access to the affected\n",
      "host, possibly at an administrative level.\n",
      "\n",
      "This may be due to a known issue with some versions of Ubuntu's\n",
      "libpam-runtime package when used in a non-default manner, although\n",
      "Nessus has not tried to verify the underlying cause."
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.launchpad.net/ubuntu/+source/pam/+bug/410171"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.ubuntu.com/usn/usn-828-1"
  );
  script_set_attribute(
    attribute:"solution",
    value:string(
      "If the remote host is running Ubuntu, upgrade to libpam-runtime\n",
      "1.0.1-4ubuntu5.6 / 1.0.1-9ubuntu1.1 or later.\n\n",
      "Otherwise, make sure the root account is secured with a strong\n",
      "password, and SSH is configured to require authentication."
    )
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
  );
  script_set_attribute(
    attribute:"vuln_publication_date",
    value:"2009/08/07"  # when this issue was posted to the Ubuntu bug tracker
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/09/15"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencie("find_service1.nasl", "ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);

  exit(0);
}


include("global_settings.inc");
include("default_account.inc");


user = 'root';
pass1 = string(SCRIPT_NAME, unixtime());
pass2 = string(SCRIPT_NAME, rand());

port = check_account(login:user, password:pass1);

if (!port)
  exit(0, "The system is not affected.");
else if (report_paranoia == 2)
{
  security_hole(port);
  exit(0);
}

# If paranoia isn't high, try to login again using a different password, just to
# make sure the system really will let us login with any password
port = check_account(login:user, password:pass2);

if (port) security_hole(port);

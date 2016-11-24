#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(38735);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2009-0025");
  script_bugtraq_id(33151);
  script_xref(name:"OSVDB", value:"51368");
  script_xref(name:"Secunia", value:"33404");
  
  script_name(english:"ISC BIND 9 EVP_VerifyFinal() / DSA_do_verify() SSL/TLS Signature Validation Weakness");
  script_summary(english:"Checks the version of BIND");

  script_set_attribute(attribute:"synopsis", value:
"The remote name server is affected by a signature validation
weakness." );
  script_set_attribute(attribute:"description", value:
"According to its version number, the remote installation of BIND does
not properly check the return value from the OpenSSL library functions
'EVP_VerifyFinal()' and 'DSA_do_verify()'.  A remote attacker may be
able to exploit this weakness to spoof answers returned from zones for
signature checks on DSA and ECDSA keys used with SSL / TLS." );
  script_set_attribute(attribute:"see_also", value:"https://www.isc.org/node/389" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to BIND 9.3.6-P1 / 9.4.3-P1 / 9.5.1-P1 / 9.6.0-P1 or later." );
  script_set_attribute(attribute:"cvss_vector", value: "
CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");
  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
  script_dependencies("bind_version.nasl", "dnssec_resolver.nasl");
  script_require_keys("bind/version", "DNSSEC/udp/53");

  exit(0);
}

include("global_settings.inc");

if (report_paranoia < 2) exit(0);

# nb: don't bother if the host doesn't support DNSSEC.
if (isnull(get_kb_item("DNSSEC/udp/53"))) exit(0);


ver = get_kb_item("bind/version");
if (
  ver &&
  ver =~ "^9\.([0-2]\.[0-9\.]+|3\.([0-5]{1}|6$)|4\.([0-2]{1}|3$)|5\.(0{1}|1$)|6\.0$)"
)
{
  if (report_verbosity > 0)
  {
    report = string(
      "\n",
      "BIND ", ver, " appears to be installed on the remote host.\n"
    );
    security_warning(port:53, proto:"udp", extra:report);
  }
  else security_warning(port:53, proto:"udp");
}

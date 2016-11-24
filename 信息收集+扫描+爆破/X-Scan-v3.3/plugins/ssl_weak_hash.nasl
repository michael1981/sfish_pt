#
# (C) Tenable Network Security, Inc.
#


if ( NASL_LEVEL < 3208 ) exit(0);



include("compat.inc");

if (description)
{
  script_id(35291);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2004-2761");
  script_bugtraq_id(11849, 33065);
  script_xref(name:"OSVDB", value:"45106");
  script_xref(name:"OSVDB", value:"45108");
  script_xref(name:"OSVDB", value:"45127");

  script_name(english:"SSL Certificate Signed using Weak Hashing Algorithm");
  script_summary(english:"Checks signature algorithm used to sign a SSL certificate");
 
 script_set_attribute(attribute:"synopsis", value:
"The SSL certificate has been signed using a weak hash algorithm." );
 script_set_attribute(attribute:"description", value:
"The remote service uses an SSL certificate that has been signed using
a cryptographically weak hashing algorithm - MD2, MD4, or MD5.  These
algorithms are known to be vulnerable to collision attacks.  In
theory, a determined attacker may be able to leverage this weakness to
generate another certificate with the same digital signature, which
could allow him to masquerade as the affected service." );
 script_set_attribute(attribute:"see_also", value:"http://tools.ietf.org/html/rfc3279" );
 script_set_attribute(attribute:"see_also", value:"http://www.phreedom.org/research/rogue-ca/" );
 script_set_attribute(attribute:"see_also", value:"http://www.microsoft.com/technet/security/advisory/961509.mspx" );
 script_set_attribute(attribute:"see_also", value:"http://www.kb.cert.org/vuls/id/836068" );
 script_set_attribute(attribute:"solution", value:
"Contact the Certificate Authority to have the certificate reissued." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"General");
 
  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("find_service.nasl");
  script_require_keys("Transport/SSL");

  exit(0);
}


include("global_settings.inc");
include("x509_func.inc");


# Make sure a port is open and supports SSL.
port = get_kb_item("Transport/SSL");
if (!port || !get_port_state(port)) exit(0);


# Retrieve and parse the cert.
cert = get_server_cert(port:port, encoding:"der");
if (isnull(cert)) exit(0);

cert = parse_der_cert(cert:cert);
if (isnull(cert)) exit(0);


# Report any using weak hash algorithms.
sig_hash = cert["signatureAlgorithm"];
if (
  sig_hash && 
  (
    sig_hash == "1.2.840.113549.1.1.4" ||                   # MD5
    sig_hash == "1.2.840.113549.1.1.3" ||                   # MD4
    sig_hash == "1.2.840.113549.1.1.2"                      # MD2
  )
)
{
  info = dump_certificate(cert:cert);
  if (report_verbosity > 1 && info)
  {
    report = string(
      "\n",
      "Here is the service's SSL certificate :\n",
      "\n",
      info
    );
    security_note(port:port, extra:report);
  }
  else security_note(port);
}

# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200402-07.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description)
{
 script_id(14451);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200402-07");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200402-07 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200402-07
(Clam Antivirus DoS vulnerability)


    Oliver Eikemeier of Fillmore Labs discovered the overflow in Clam AV 0.65
    when it handled malformed UUEncoded messages, causing the daemon to shut
    down.
    The problem originated in libclamav which calculates the line length of an
    uuencoded message by taking the ASCII value of the first character minus 64
    while doing an assertion if the length is not in the allowed range,
    effectively terminating the calling program as clamav would not be
    available.
  
Impact

    A malformed message would cause a denial of service,
    and depending on the server configuration this may impact other daemons
    relying on Clam AV in a fatal manner.
  
Workaround

    There is no immediate workaround, a software upgrade is required.
  
');
script_set_attribute(attribute:'solution', value: '
    All users are urged to upgrade their Clam AV installations to Clam AV 0.67:
    # emerge sync
    # emerge -pv ">=app-antivirus/clamav-0.6.7"
    # emerge ">=app-antivirus/clamav-0.6.7"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Medium');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200402-07.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200402-07] Clam Antivirus DoS vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Clam Antivirus DoS vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-antivirus/clamav", unaffected: make_list("ge 0.67"), vulnerable: make_list("lt 0.67")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");

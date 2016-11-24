# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200505-05.xml
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
 script_id(18231);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200505-05");
 script_cve_id("CVE-2005-0758", "CVE-2005-0988", "CVE-2005-1228");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200505-05 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200505-05
(gzip: Multiple vulnerabilities)


    The gzip and gunzip programs are vulnerable to a race condition
    when setting file permissions (CAN-2005-0988), as well as improper
    handling of filename restoration (CAN-2005-1228). The zgrep utility
    improperly sanitizes arguments, which may come from an untrusted source
    (CAN-2005-0758).
  
Impact

    These vulnerabilities could allow arbitrary command execution,
    changing the permissions of arbitrary files, and installation of files
    to an aribitrary location in the filesystem.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All gzip users should upgrade to the latest stable version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-arch/gzip-1.3.5-r6"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0758');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0988');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-1228');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200505-05.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200505-05] gzip: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'gzip: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-arch/gzip", unaffected: make_list("ge 1.3.5-r6"), vulnerable: make_list("lt 1.3.5-r6")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");

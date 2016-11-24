# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200501-33.xml
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
 script_id(16424);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200501-33");
 script_cve_id("CVE-2005-0004");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200501-33 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200501-33
(MySQL: Insecure temporary file creation)


    Javier Fernandez-Sanguino Pena from the Debian Security Audit
    Project discovered that the \'mysqlaccess\' script creates temporary
    files in world-writeable directories with predictable names.
  
Impact

    A local attacker could create symbolic links in the temporary
    files directory, pointing to a valid file somewhere on the filesystem.
    When the mysqlaccess script is executed, this would result in the file
    being overwritten with the rights of the user running the software,
    which could be the root user.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All MySQL users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-db/mysql-4.0.22-r2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0004');
script_set_attribute(attribute: 'see_also', value: 'http://secunia.com/advisories/13867/');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200501-33.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200501-33] MySQL: Insecure temporary file creation');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'MySQL: Insecure temporary file creation');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-db/mysql", unaffected: make_list("ge 4.0.22-r2"), vulnerable: make_list("lt 4.0.22-r2")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");

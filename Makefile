all: shellcheck README

shellcheck:
	shellcheck jenkins-bootstrap.sh

README:
	( cat README.md.inc ; printf "\n---\n\n" ; ./jenkins-bootstrap.sh | sed -e 's/^/    /g' ) > README.md


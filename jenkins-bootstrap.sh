#!/usr/bin/env sh
# bootstrap-jenkins.sh - build a Jenkins container and install systemd service to run it
# Copyright (2020-2022) Peter Willis
#
# shellcheck disable=SC1090,SC2016,SC1004

set -eu
# Set 'DEBUG=1' to enable trace mode
[ "${DEBUG:-0}" = "1" ] && set -x

# This is a file on the local system which will have a random password, which can
# be used to configure the initial Jenkins admin user
JENKINS_INITIAL_PW_FILE="${JENKINS_INITIAL_PW_FILE:-/etc/bootstrap/jenkins_initial_pw}"

LOCAL_USER="${LOCAL_USER:-$(id -un)}"
LOCAL_USER_ID="${LOCAL_USER_ID:-$(id -u "$LOCAL_USER")}"
LOCAL_GROUP="${LOCAL_GROUP:-$LOCAL_USER}"
LOCAL_GROUP_ID="${LOCAL_GROUP_ID:-$(id -g "$LOCAL_GROUP")}"
LOCAL_USER_HOME="${LOCAL_USER_HOME:-$(getent passwd "$LOCAL_USER" | cut -d : -f 6)}"
LOCAL_JENKINS_HOME="${LOCAL_JENKINS_HOME:-$LOCAL_USER_HOME/jenkins/jenkins_home}"  # JENKINS_HOME local directory

JENKINS_VERSION_TAG="${JENKINS_VERSION_TAG:-lts}"                         # jenkins/jenkins:TAG to build from
JENKINS_DOCKER_IMG_NAME="${JENKINS_DOCKER_IMG_NAME:-jenkins-controller}"  # Our container's name
JENKINS_DOCKER_IMG_TAG="${JENKINS_DOCKER_IMG_TAG:-latest}"                # Our container's tag
JENKINS_FILES_DIR="${JENKINS_FILES_DIR:-.}"                               # Directory with plugins.txt/jcasc.d
JENKINS_LOG_LEVEL="${JENKINS_LOG_LEVEL:-INFO}"

SVC_WRAP_ENVRC="${SVC_WRAP_ENVRC:-/etc/bootstrap/env}" # a file to load env vars from before starting jenkins

# An optional SSH key that the default JCasC configures for use as /run/secrets/BOOTSTRAP_SSH_KEY
SSH_KEY_FILE="${SSH_KEY_FILE:-/etc/bootstrap/ssh_key}"

SUDO="${SUDO:-$(command -v sudo || true)}"

JENKINS_PLUGINS_DEFAULT="
# Base plugins
ace-editor
active-directory
amazon-ecr
amazon-ecs
ansicolor
antisamy-markup-formatter
apache-httpcomponents-client-4-api
authentication-tokens
aws-credentials
aws-parameter-store
bootstrap4-api
bootstrap5-api
bouncycastle-api
branch-api
build-timeout
caffeine-api
checks-api
cloudbees-folder
command-launcher
conditional-buildstep
configuration-as-code
configuration-as-code-groovy
configuration-as-code-secret-ssm
credentials
credentials-binding
display-url-api
docker-commons
docker-java-api
docker-plugin
docker-workflow
durable-task
ec2-fleet
echarts-api
font-awesome-api
git
git-client
github
github-api
github-branch-source
github-oauth
git-server
handlebars
jackson2-api
javax-activation-api
javax-mail-api
jaxb
jdk-tool
jjwt-api
job-dsl
jquery3-api
jsch
junit
ldap
lockable-resources
mailer
matrix-auth
matrix-project
metrics
momentjs
oic-auth
okhttp-api
parameterized-trigger
pipeline-aws
pipeline-build-step
pipeline-github-lib
pipeline-graph-analysis
pipeline-input-step
pipeline-milestone-step
pipeline-model-api
pipeline-model-definition
pipeline-model-extensions
pipeline-rest-api
pipeline-stage-step
pipeline-stage-tags-metadata
pipeline-stage-view
plain-credentials
plugin-util-api
popper2-api
popper-api
role-strategy
run-condition
saml
scm-api
snakeyaml-api
sonar
ssh-credentials
sshd
ssh-slaves
strict-crumb-issuer
structs
timestamper
token-macro
trilead-api
variant
workflow-aggregator
workflow-api
workflow-basic-steps
workflow-cps
workflow-cps-global-lib
workflow-durable-task-step
workflow-job
workflow-multibranch
workflow-scm-step
workflow-step-api
workflow-support

# Extra plugins
build-pipeline-plugin
delivery-pipeline-plugin
nested-view
parameterized-scheduler
pollscm
slack-uploader
ssh-agent

# Used to trigger seed job when Jenkins starts
startup-trigger-plugin

# Disable script security. Requires also calling Jenkins with -Dpermissive-script-security.enabled=true
permissive-script-security
"

JCASC_CONFIG_FILE_DEFAULT='
credentials:
  system:
    domainCredentials:
      - credentials:
        - basicSSHUserPrivateKey:
            scope: GLOBAL
            id: "jenkins-bootstrap-ssh-key"
            description: "The SSH key used to bootstrap the Jenkins instance"
            privateKeySource:
              directEntry:
                privateKey: "${BOOTSTRAP_SSH_KEY}"
            username: "git"

#jenkins:
#  globalNodeProperties:
#    - envVars:
#        env:
#          - key: "ENVIRONMENT"
#            value: "dev"
#          - key: "REGION"
#            value: "us-east-1"

jenkins:
  authorizationStrategy:
    loggedInUsersCanDoAnything:
      allowAnonymousRead: false
  securityRealm:
    local:
      allowsSignup: false
      enableCaptcha: false
      users:
      - id: "admin"
        name: "admin"
        password: "${JENKINS_INITIAL_PW}"
  noUsageStatistics: true
  systemMessage: "Jenkins configured automatically by Jenkins Configuration as Code plugin\n\n"
  numExecutors: 10
  scmCheckoutRetryCount: 2
  # Only allow jobs with "jenkins-controller" label to run on controller. The docker cloud
  # configured below runs any build job using the Docker Cloud build agent template.
  mode: EXCLUSIVE # set to NORMAL to allow running any jobs on the master
  labelString: "jenkins-controller"
  agentProtocols:
  - "JNLP4-connect"
  - "Ping"
  slaveAgentPort: 50000
  crumbIssuer:
    standard:
      excludeClientIPFromCrumb: false
  remotingSecurity:
    enabled: true
  clouds:
  - docker:
      dockerApi:
        connectTimeout: 30
        dockerHost:
          uri: "unix:///var/run/docker.sock"
        readTimeout: 30
      exposeDockerHost: true
      name: "local-docker"
      templates:
      - connector: "attach"
        dockerTemplateBase:

          # FYI: the Docker plugin can only run containers from Docker Hub, it
          # will not run containers that only live on the local host! You will
          # have to configure a custom registry and reference the container
          # here to run non-Docker Hub containers as build agents.
          image: "jenkins/jnlp-slave"
          #image: "my-docker-registry/jenkins-agent:latest-alpine"

          # Bind-mount in a default SSH key from the host, and the Docker socket.
          # This way the build agent can run Docker builds and also use an SSH
          # key without the Pipeline using withCredentials().
          # You need a /home/jenkins/.ssh folder on your local host!
          mounts:
          - "type=bind,src=/home/jenkins/.ssh,dst=/home/jenkins/.ssh"
          - "type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock"
          mountsString: |-
            type=bind,src=/home/jenkins/.ssh,dst=/home/jenkins/.ssh
            type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock

          # You need this if you use a private Docker registry
          #pullCredentialsId: "svc-platform-knowled-artifactory"

        labelString: "local-docker-agent"
        #pullStrategy: PULL_ALWAYS
        pullTimeout: 300
        remoteFs: "/home/jenkins/agent"
        removeVolumes: true

unclassified:
  location:
    adminAddress: "fake@fake.fake"
    url: "https://localhost:8080/"

security:
  apiToken:
    creationOfLegacyTokenEnabled: false
    tokenGenerationOnCreationEnabled: false
    usageStatisticsEnabled: true
  globalJobDslSecurityConfiguration:
    useScriptSecurity: false
  sSHD:
    port: -1
  #scriptApproval:
  #   If you have jobs that want to run at startup and require script approval,
  #   add the methods here.
  #  approvedSignatures:
  #  - "staticMethod org.codehaus.groovy.runtime.DefaultGroovyMethods execute java.lang.String"
'

JENKINS_DOCKERFILE_DEFAULT='
FROM jenkins/jenkins:${{JENKINS_VERSION_TAG}}-alpine

ENV CASC_JENKINS_CONFIG="/var/jenkins_home/jcasc.d"
ENV JAVA_OPTS="-Djenkins.install.runSetupWizard=false -Djava.util.logging.config.file=/var/jenkins_home/logging.properties -Dpermissive-script-security.enabled=true"

USER root

# Groovy code can run commands outside of the build agents, so we bundle these
# in the jenkins-controller for convenience
RUN apk add -u --no-cache aws-cli docker-cli

# Only reinstall plugins when plugins file changes
COPY plugins.txt /var/jenkins_home/plugins.txt
RUN /usr/local/bin/install-plugins.sh `cat /var/jenkins_home/plugins.txt | grep -v ^# `

# Copy everything else to avoid busting plugin install cache
COPY --chown=jenkins:jenkins . /var/jenkins_home/

# Fix permissions and user/group IDs to match the local host
RUN set -e -x; \
    sed -i -e "s/^\(jenkins:x\):[0-9]\+:[0-9]\+:\(.*\)$/\1:${{LOCAL_USER_ID}}:${{LOCAL_GROUP_ID}}:\2/" /etc/passwd ; \
    sed -i -e "s/^\(jenkins:x\):[0-9]\+:$/\1:${{LOCAL_GROUP_ID}}:/" /etc/group ; \
    echo "docker:x:${{DOCKER_GID}}:jenkins" >> /etc/group ; \
    chmod -v 755 /var/jenkins_home/entrypoint.sh

HEALTHCHECK --timeout=5s --interval=30s --retries=10 cmd curl -fsSL -o /dev/null localhost:8080/login

WORKDIR /var/jenkins_home

# Make sure entrypoint starts as root and not jenkins user
ENTRYPOINT ["/var/jenkins_home/entrypoint.sh"]
'

JENKINS_LOGGING_PROPERTIES_DEFAULT='
.level=${{JENKINS_LOG_LEVEL}}
handlers=java.util.logging.ConsoleHandler
java.util.logging.ConsoleHandler.level=${{JENKINS_LOG_LEVEL}}
jenkins.level=${{JENKINS_LOG_LEVEL}}
'

JENKINS_ENTRYPOINT_DEFAULT='#!/usr/bin/env bash
# entrypoint.sh - customized version of Jenkins entrypoint script
# 
# This script is modified to fix the ownership and permissions on the JENKINS_HOME
# directory before executing Jenkins. Therefore, this entrypoint should be started
# as the root user. 
# 
# The stock containers files may be owned by uid 1000, but this may need to change
# at runtime, so file ownership is changed to CHOWN_USER and CHOWN_GROUP.
# Pass JENKINS_USER to change which user is changed to before executing Jenkins.
set -e

: "${JENKINS_WAR:="/usr/share/jenkins/jenkins.war"}"
: "${JENKINS_HOME:="/var/jenkins_home"}"
: "${COPY_REFERENCE_FILE_LOG:="${JENKINS_HOME}/copy_reference_file.log"}"
: "${REF:="/usr/share/jenkins/ref"}"
CHOWN_USER="${CHOWN_USER:-jenkins}"
CHOWN_GROUP="${CHOWN_GROUP:-jenkins}"
JENKINS_USER="${JENKINS_USER:-jenkins}"

# If running as root, fix jenkins permissions and re-run as user jenkins
if [ "$(id -u)" = "0" ] ; then
    chown "$CHOWN_USER:$CHOWN_GROUP" "$JENKINS_HOME"
    # Dont use -uid (doesnt work in busybox find), use -user
    find /usr /var -user 1000 -exec chown "$CHOWN_USER:$CHOWN_GROUP" {} \; ; \
    for d in logs jobs workspace .ssh ; do
        [ -d "$JENKINS_HOME/$d" ] || mkdir -p "$JENKINS_HOME/$d"
        chown "$CHOWN_USER:$CHOWN_GROUP" "$JENKINS_HOME/$d"
    done
    exec su -p "$JENKINS_USER" -- -c "$0 $*"
fi

# Make sure HOME is whatevers set in /etc/passwd
# shellcheck disable=SC2155
export HOME="$(getent passwd jenkins | cut -d : -f 6)"

cd "$JENKINS_HOME"

touch "${COPY_REFERENCE_FILE_LOG}" || { echo "Can not write to ${COPY_REFERENCE_FILE_LOG}. Wrong volume permissions?"; exit 1; }
echo "--- Copying files at $(date)" >> "$COPY_REFERENCE_FILE_LOG"
find "${REF}" \( -type f -o -type l \) -exec bash -c ". /usr/local/bin/jenkins-support; for arg; do copy_reference_file "\$arg"; done" _ {} +

# if `docker run` first argument start with `--` the user is passing jenkins launcher arguments
if [[ $# -lt 1 ]] || [[ "$1" == "--"* ]]; then

  # read JAVA_OPTS and JENKINS_OPTS into arrays to avoid need for eval (and associated vulnerabilities)
  java_opts_array=()
  while IFS= read -r -d "" item; do
    java_opts_array+=( "$item" )
  done < <([[ $JAVA_OPTS ]] && xargs printf "%s\\0" <<<"$JAVA_OPTS")

  readonly agent_port_property="jenkins.model.Jenkins.slaveAgentPort"
  if [ -n "${JENKINS_SLAVE_AGENT_PORT:-}" ] && [[ "${JAVA_OPTS:-}" != *"${agent_port_property}"* ]]; then
    java_opts_array+=( "-D${agent_port_property}=${JENKINS_SLAVE_AGENT_PORT}" )
  fi

  if [[ "$DEBUG" ]] ; then
    java_opts_array+=( \
      "-Xdebug" \
      "-Xrunjdwp:server=y,transport=dt_socket,address=*:5005,suspend=y" \
    )
  fi

  jenkins_opts_array=( )
  while IFS= read -r -d "" item; do
    jenkins_opts_array+=( "$item" )
  done < <([[ $JENKINS_OPTS ]] && xargs printf "%s\\0" <<<"$JENKINS_OPTS")

  FUTURE_OPTS=""
  if [[ "$JENKINS_ENABLE_FUTURE_JAVA" ]] ; then
    FUTURE_OPTS="--add-opens java.base/java.lang=ALL-UNNAMED
        --add-opens=java.base/java.io=ALL-UNNAMED
        --add-opens java.base/java.util=ALL-UNNAMED
        --add-opens java.base/java.util.concurrent=ALL-UNNAMED
        "
  fi

  # --add-opens wont get expanded properly with quotes around it
  # shellcheck disable=SC2086
  exec java -Duser.home="$JENKINS_HOME" ${FUTURE_OPTS} "${java_opts_array[@]}" -jar ${JENKINS_WAR} "${jenkins_opts_array[@]}" "$@"
fi

# As argument is not jenkins, assume user wants to run a different process, for example a `bash` shell to explore this image
exec "$@"
'

# Default Systemd service file.
# Note that this volume-mounts only the directories 'logs', 'jobs', 'workspace'.
# All other Jenkins files are kept in the Docker container. This keeps Jenkins files
# from persisting across restarts, minimizing dependence on state, and making it
# easier to switch versions without old files causing conflicts.
# This also volume-mounts the initial random password into /run/secrets/ so that
# JCasC can reference it.
# Also note that '--env-file' used by Docker is key=value pairs, but they must
# not contain quotes ("") around the value.
# ${VARIABLE} entries here are replaced later by shell environment variables
JENKINS_SYSTEMD_CONFIG_DEFAULT='
[Unit]
Description=Jenkins Controller
Documentation=https://jenkins.io/doc/
After=docker.service
Requires=docker.service

[Service]
Type=simple
User=${{LOCAL_USER}}
Group=${{LOCAL_GROUP}}
TimeoutStartSec=0
Restart=on-failure
RestartSec=15s
ExecStartPre=-/usr/bin/docker kill jenkins-controller
ExecStartPre=-/usr/bin/docker rm jenkins-controller
ExecStart=/usr/local/bin/jenkins-svc-wrap
SyslogIdentifier=jenkins-controller
ExecStop=/usr/bin/docker stop jenkins-controller

[Install]
WantedBy=multi-user.target
'

JENKINS_SVC_WRAP_DEFAULT='#!/usr/bin/env sh
[ "${DEBUG:-0}" = "1" ] && set -x

SUDO="${SUDO:-$(command -v sudo || true)}"
LOCAL_JENKINS_HOME="${LOCAL_JENKINS_HOME:-${{LOCAL_JENKINS_HOME}}}"
LOCAL_USER="${LOCAL_USER:-${{LOCAL_USER}}}"
LOCAL_GROUP="${LOCAL_GROUP:-${{LOCAL_GROUP}}}"

$SUDO chown "$LOCAL_USER:$LOCAL_GROUP" "$LOCAL_JENKINS_HOME"
for d in logs jobs workspace ; do
    [ -d "$LOCAL_JENKINS_HOME/$d" ] || $SUDO mkdir -p "$LOCAL_JENKINS_HOME/$d"
    $SUDO chown "$LOCAL_USER:$LOCAL_GROUP" "$LOCAL_JENKINS_HOME/$d"
done

# Generate a Docker --env-file from a regular bash script
tmpfile="$(mktemp)"
if [ -n "${{SVC_WRAP_ENVRC}}" ] && [ -e "${{SVC_WRAP_ENVRC}}" ] && [ -s "${{SVC_WRAP_ENVRC}}" ] ; then
    set -a
    . "${{SVC_WRAP_ENVRC}}"
    grep = "${{SVC_WRAP_ENVRC}}" \
        | cut -d = -f 1 \
        | xargs -n1 -I{} /bin/sh -c "printf \"%s\n\" \"{}=${}\"" \
        > "$tmpfile"
fi

/usr/bin/docker run \
    --rm \
    --name jenkins-controller \
    --publish 8080:8080 \
    --publish 50000:50000 \
    --volume "$LOCAL_JENKINS_HOME/logs:/var/jenkins_home/logs" \
    --volume "$LOCAL_JENKINS_HOME/jobs:/var/jenkins_home/jobs" \
    --volume "$LOCAL_JENKINS_HOME/workspace:/var/jenkins_home/workspace" \
    --volume /var/run/docker.sock:/var/run/docker.sock \
    --env-file "$tmpfile" \
    --volume /run/secrets:/run/secrets \
    --volume ${{JENKINS_INITIAL_PW_FILE}}:/run/secrets/JENKINS_INITIAL_PW \
    --volume ${{SSH_KEY_FILE}}:/run/secrets/BOOTSTRAP_SSH_KEY \
    ${{JENKINS_DOCKER_IMG_NAME}}:${{JENKINS_DOCKER_IMG_TAG}}
ret=$?

rm -f "$tmpfile"
exit $ret
'



##############################################################################################

_cmd_install_tools () {	### Install the system tools used by this script
    if command -v yum ; then
        $SUDO yum upgrade -y
        for PKG in ca-certificates curl gnupg2 jq ; do rpm -q $PKG || $SUDO yum install -y $PKG ; done
    elif command -v apt-get ; then
        $SUDO apt-get update
        $SUDO apt-get upgrade -y
        for PKG in ca-certificates curl gnupg2 jq ; do dpkg -l $PKG || $SUDO apt-get install -y $PKG ; done
    fi
}

_cmd_install_docker () {	### Install the latest stable version of Docker (should work for any Linux distro)
    if ! command -v docker >/dev/null ; then
        if command -v amazon-linux-extras 2>/dev/null 1>&2 ; then
            amazon-linux-extras install -y docker
        else
            curl -fsSL https://get.docker.com -o get-docker.sh
            $SUDO sh get-docker.sh
        fi
    fi
    # Add the $LOCAL_USER to the docker group
    if ! getent group docker | cut -d : -f 4- | grep -q "$LOCAL_USER" ; then
        if command -v usermod     ; then $SUDO usermod -aG docker "$LOCAL_USER"
        elif command -v addgroup  ; then $SUDO addgroup "$LOCAL_USER" docker
        fi
    fi
    # Make sure Docker is started
    if command -v systemctl 2>/dev/null 1>&2 ; then
        $SUDO systemctl daemon-reload
        $SUDO systemctl start docker
        $SUDO systemctl enable docker
    fi
}

# Substitute ${{FOO}} for $FOO in any files with .tmpl extension.
# Write to the same file name without the .tmpl extension.
_process_tmpl_files () {
    # Set DOCKER_GID as late as possible in case Docker was just installed prior to this
    DOCKER_GID="${DOCKER_GID:-$(getent group docker | cut -d : -f 3)}"
    find . -type f -iname '*.tmpl' | while read -r f ; do
        dn="$(dirname "$f")"  bn="$(basename "$f" .tmpl)"
        _envsubst < "$f" > "$f.tmp" \
        && cp -v -f "$f.tmp" "$dn/$bn" \
        && rm -f "$f.tmp" "$f" # removes '.tmpl' file as well as temp file
    done
}
_copy_files_from () {
    dir="$1"; shift
    if [ $# -gt 0 ] ; then
        for f in "$@" ; do
            [ -e "$dir/$f" ] && _copy_file "$dir/$f"
        done
    else
        for f in "$dir"/.??* "$dir"/* ; do
            bn="$(basename "$f")"
            if [ "$bn" = ".??*" ] || [ "$bn" = "*" ] ; then continue ; fi
            [ -e "$f" ] && _copy_file "$f"
        done
    fi
}
_copy_file () {
    if ! cp -v -p -L -r "$1" . ; then
        echo "$0: Error: could not copy file '$1'" ; exit 1
    fi
}
# only create a default file if a src_file does not exist
_create_default_file () {
    default_text="$1" dest_file="$2"; shift 2
    for src_file in "$@" ; do [ -e "$src_file" ] && return 0 ; done
    printf "%s\n" "$default_text" > "$dest_file"
}
_touch_file () {
    [ -d "$(dirname "$1")" ] || $SUDO mkdir -p "$(dirname "$1")"
    [ -e "$1" ] || $SUDO touch "$1"
}
_install_file () {
    _touch_file "$2"
    $SUDO mv -f -v "$1" "$2"
}
# Create a temp dir, move to it, do stuff, clean up temp dir after, return last status
_tmpd_wrap () {
    opwd="$(pwd)" tmpdir="$(mktemp -d)"
    cd "$tmpdir"
    "$@" # call functions w/args
    ret=$?
    rm -rf "$tmpdir"
    cd "$opwd"
    return $ret
}
_create_initial_admin_pw () {
    # Create admin password (on the local host! not the container!).
    # Configs can use this if they wish to use a hard-coded random password for an admin user
    # into a container's configs (for example with the generated jcasc.d/jenkins.yml file below).
    # 
    # HOWEVER: anyone with access to the Docker image will be able to read the password if it's saved
    # in the container. Therefore, use JCasC's secrets mechanisms to load a password at runtime:
    # https://github.com/jenkinsci/configuration-as-code-plugin/blob/master/docs/features/secrets.adoc
    # 
    RANDOM_PW="$(head /dev/urandom | LC_ALL=C tr -dc A-Za-z0-9 | head -c 20)"
    if [ -n "${JENKINS_INITIAL_PW_FILE:-}" ] && [ ! -e "$JENKINS_INITIAL_PW_FILE" ] ; then
        touch "$JENKINS_INITIAL_PW_FILE" || true
        [ -d "$(dirname "$JENKINS_INITIAL_PW_FILE")" ] || $SUDO mkdir -p "$(dirname "$JENKINS_INITIAL_PW_FILE")"
        printf "%s\n" "$RANDOM_PW" | $SUDO tee "$JENKINS_INITIAL_PW_FILE" >/dev/null
        $SUDO chmod 0600 "$JENKINS_INITIAL_PW_FILE"
        $SUDO chown "$LOCAL_USER":"$LOCAL_GROUP" "$JENKINS_INITIAL_PW_FILE"
    fi
}

_cmd_build_controller_container () {	### Build Jenkins Controller container, including $JENKINS_PLUGINS_FILE
    _tmpd_wrap _build_controller_container
}
_build_controller_container () {
    _create_initial_admin_pw

    # Copy over user-supplied Jenkins customizations
    _copy_files_from "$JENKINS_FILES_DIR"

    # Create defaults
    _create_default_file "$JENKINS_PLUGINS_DEFAULT" "plugins.txt.tmpl" "plugins.txt.tmpl" "plugins.txt"
    _create_default_file "$JENKINS_DOCKERFILE_DEFAULT" "Dockerfile.tmpl" "Dockerfile.tmpl" "Dockerfile"
    _create_default_file "$JENKINS_ENTRYPOINT_DEFAULT" "entrypoint.sh.tmpl" "entrypoint.sh.tmpl" "entrypoint.sh"
    _create_default_file "$JENKINS_LOGGING_PROPERTIES_DEFAULT" "logging.properties.tmpl" "logging.properties.tmpl" "logging.properties"
    mkdir -p jcasc.d .ssh
    _create_default_file "$JCASC_CONFIG_FILE_DEFAULT" "jcasc.d/jenkins.yaml.tmpl" "jcasc.d/jenkins.yaml.tmpl" "jcasc.d/jenkins.yaml"
    [ -e ".ssh/known_hosts" ] || ssh-keyscan github.com > .ssh/known_hosts

    # Convert templates to real files
    _process_tmpl_files

    # Hack: I don't know why the Dockerfile can't fix these permissions!
    chmod 755 -- *.sh || true

    if [ "${DEBUG:-0}" = "1" ] ; then
        echo "$0: jcasc.d/" 1>&2; grep -H -e "" -r jcasc.d 1>&2
        echo "$0: Dockerfile:" 1>&2; grep -H -e "" Dockerfile 1>&2
    fi

    # The build context of the container is the temp dir, because the temp dir
    # contains whole copies of files and no symlinks. You can also pass
    # JENKINS_DOCKER_CONTEXT to set a specific context.
    if ! docker build \
        -t "$JENKINS_DOCKER_IMG_NAME":"$JENKINS_DOCKER_IMG_TAG" \
        "${JENKINS_DOCKER_CONTEXT:-$tmpdir}"
    then
        echo "$0: ERROR: 'docker build' failed!"
        exit 1
    fi
}

_cmd_install_controller_service () {	### Install the systemd service for the Jenkins Controller
    _tmpd_wrap _install_controller_service
}
_install_controller_service () {
    _touch_file "${SSH_KEY_FILE}"

    # Copy custom files
    _copy_files_from "$JENKINS_FILES_DIR" "jenkins-svc-wrap.tmpl" "jenkins-svc-wrap"
    _copy_files_from "$JENKINS_FILES_DIR" "jenkins-controller.service.tmpl" "jenkins-controller.service"

    # Create defaults
    _create_default_file "$JENKINS_SVC_WRAP_DEFAULT" "jenkins-svc-wrap.tmpl" "jenkins-svc-wrap.tmpl" "jenkins-svc-wrap"
    _create_default_file "$JENKINS_SYSTEMD_CONFIG_DEFAULT" "jenkins-controller.service.tmpl" "jenkins-controller.service.tmpl" "jenkins-controller.service"
    
    # Convert templates to real files
    _process_tmpl_files

    # Install system-wide files
    _install_file "jenkins-svc-wrap" "/usr/local/bin/jenkins-svc-wrap"
    _install_file "jenkins-controller.service" "/etc/systemd/system/jenkins-controller.service"
    $SUDO chmod 755 "/usr/local/bin/jenkins-svc-wrap" "/etc/systemd/system/jenkins-controller.service"

    if command -v systemctl 2>/dev/null 1>&2 ; then
        $SUDO systemctl daemon-reload
        $SUDO systemctl enable jenkins-controller
    fi
}

_cmd_start_controller_service () {	### Fix jenkins permissions and enable/start jenkins-controller systemd service
    if command -v systemctl 2>/dev/null 1>&2 ; then
        $SUDO systemctl daemon-reload
        $SUDO systemctl start jenkins-controller
        $SUDO systemctl enable jenkins-controller
    fi
}

_cmd_wait_for_login () {	### Run 'curl http://localhost:8080/login' until page comes back successful, or time out
    remote_uri="${1:-localhost:8080/login}"
    CURL_TIMEOUT="${CURL_TIMEOUT:-5}"
    CURL_RETRIES="${CURL_RETRIES:-60}"
    CURL_INTERVAL="${CURL_INTERVAL:-15}"
    # shellcheck disable=SC2034
    c=0
    while [ $c -lt "$CURL_RETRIES" ] ; do
        if curl -fsSL --connect-timeout "${CURL_TIMEOUT}" "$remote_uri" ; then
            return 0
        else
            echo "$0: Curl '$remote_uri' failed; retrying"
        fi
        sleep "${CURL_INTERVAL}"
        c=$((c+1))
    done
    return 1
}

_cmd_dump_plugins () {	### Arguments: baseurl, username, password
    JENKINS_BASEURL="${JENKINS_BASEURL:-$1}"
    JENKINS_USER="${JENKINS_USER:-$2}"
    JENKINS_PASSWORD="${JENKINS_PASSWORD:-$3}"
    GET_PLUGIN_GROOVY='for (plugin in Jenkins.instance.pluginManager.plugins) { println("${plugin.getShortName()}=${plugin.getVersion()}") }'
    cookiejar="$(mktemp)"
    crumb=$(curl -fsSL -u "$JENKINS_USER:$JENKINS_PASSWORD" --cookie-jar "$cookiejar" "$JENKINS_BASEURL/crumbIssuer/api/xml?xpath=concat(//crumbRequestField,%22:%22,//crumb)")
    curl -fsSL -d "script=$GET_PLUGIN_GROOVY" -u "$JENKINS_USER:$JENKINS_PASSWORD" --cookie "$cookiejar" -H "$crumb" "$JENKINS_BASEURL"/scriptText
    rm -f "$cookiejar"
}

_cmd_all () {	### install_tools, install_docker, build_controller_container [ARGS ..], install_controller_service, start_controller_service
    _cmd_install_tools
    _cmd_install_docker
    _cmd_build_controller_container "$@"
    _cmd_install_controller_service
    _cmd_start_controller_service
}

# Replace ${{FOO}} with the value of $FOO
_envsubst () {
    set +e ; while IFS= read -r foo ; do
        while : ; do
            match="$(expr "$foo" : '^.*{{\([a-zA-Z0-9_]\+\)}}.*$')"
            [ -n "$match" ] || break
            eval new="\${$match:-}"
            # shellcheck disable=SC2154
            foo="$(printf "%s\n" "$foo" | sed -e "s?\${{$match}}?$new?g")"
            continue
        done
        printf "%s\n" "$foo"
    done ; set -e
}

_shutdown () {
    if [ "${SHUTDOWN:-0}" = "1" ] ; then
        echo "$0: Shutting down server in 1 minute." 1>&2
        /sbin/shutdown -h +1
    fi
    exit 1
}

_cmd_docker_local_build () {	### Build a jenkins-controller container from your local machine
	env \
      LOCAL_USER_ID="$(id -u)" \
      LOCAL_GROUP_ID="$(id -g)" \
      DOCKER_GID="${DOCKER_GID:-$(getent group docker | cut -d : -f 3)}" \
      JENKINS_FILES_DIR="$(pwd)/jenkins" \
      JENKINS_INITIAL_PW_FILE="$(pwd)/jenkins_pw.txt" \
      "$0" build_controller_container
}

_cmd_docker_local_run () {	### Run the jenkins-controller container locally in Docker
    set -eux
    docker stop jenkins-controller || true

    # Make sure AWS_REGION is specified or configuration-as-code-secret-ssm won't work
    AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-us-east-1}"
    AWS_REGION="${AWS_REGION:-$AWS_DEFAULT_REGION}"

    docker run --rm -d \
        --name jenkins-controller \
        --publish 8080:8080 --publish 50000:50000 \
        --volume /var/run/docker.sock:/var/run/docker.sock \
        --volume "$(pwd)/jenkins_pw.txt":/run/secrets/JENKINS_INITIAL_PW \
        --volume "$HOME/.ssh/id_rsa":/run/secrets/BOOTSTRAP_SSH_KEY \
        -e AWS_ACCESS_KEY_ID -e AWS_SDK_LOAD_CONFIG -e AWS_SECRET_ACCESS_KEY -e AWS_SESSION_TOKEN \
        -e "AWS_DEFAULT_REGION=$AWS_REGION" -e "AWS_REGION=$AWS_REGION" \
        jenkins-controller:latest
        "$0" wait_for_login
}

_usage () {
    cat <<EOUSAGE
Usage: $0 [COMMAND [ARG ..]]

 This script will install everything necessary on a host so that it can
 build and run a Jenkins Controller as a Docker container. A systemd service
 is included.
 
 Most variables in this script can be overridden at run time, either by
 passing it into this program on execution, or by setting the variables in
 a \$SVC_WRAP_ENVRC script.

 Pass the following environment variables to customize the 'jenkins-controller'
 container (defaults are used if these are not passed):

    LOCAL_USER=\`id -un\`             The local user who will own the
                                    LOCAL_JENKINS_HOME directory.

    LOCAL_GROUP=\`id -gn\`            The group of the same user.

    LOCAL_JENKINS_HOME=/home/\$LOCAL_USER/jenkins/jenkins_home
                                    The directory which will be volume-mounted
                                    as '/var/jenkins_home' in the container.

    JENKINS_VERSION_TAG=lts         The TAG in 'jenkins/jenkins:TAG' Dockerfile FROM

    JENKINS_LOG_LEVEL=INFO          The level of logging output Jenkins should create

    JENKINS_FILES_DIR=.             Optional directory with plugins.txt, jcasc.d, Dockerfile, entrypoint.sh, logging.properties, .ssh/known_hosts, jenkins-controller.service, jenkins-svc-wrap. Add .tmpl extension to substitute \${{FOO}} for environment variable \$FOO. Resulting files copied into /var/jenkins_home/ in the container.

    SSH_KEY_FILE=/etc/bootstrap/ssh_key
                                    An SSH key to include as a Jenkins Credential
                                    if using the default jenkins.yaml.


 Commands:
EOUSAGE
    printf "%s\n" "$(grep '^_cmd_[a-zA-Z0-9_]\+ ()' "$0" | sed -e 's/^_cmd_\([a-zA-Z0-9_]\+\) () {\t### \(.*\)$/   \1\n\t\t\t\t\2\n/g')"
    exit 1
}


##############################################################################################

SHUTDOWN=0
while getopts "Sh" args ; do
    case $args in
        S)  SHUTDOWN=1 ;;
        h)  _usage ;;
        *)  echo "$0: Error: unknown option $args" ; exit 1 ;;
    esac
done
shift $((OPTIND-1))

[ $# -gt 0 ] || _usage
if command -v _cmd_"$1" >/dev/null ; then
    cmd="$1"; shift 
    if ! _cmd_"$cmd" "$@" ; then
        _shutdown
    fi
else
    _usage
fi

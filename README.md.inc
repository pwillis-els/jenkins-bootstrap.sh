# jenkins-bootstrap.sh

## About

A Bourne shell script that will configure, build, install, and run a Jenkins server in a Docker container. Everything you need to get Jenkins up and running is included in this script.

---


## Usage

For convenience, this script allows you to supply a command to tell the script what to do, but you won't need to use most of the commands. Instead you will probably use one of the following two methods depending on your needs.


### Option 1. Install Jenkins system-wide

Use this script to install all the tools you need (Docker, Curl, CA Certificates, etc), install a Systemd unit file, build the containers, and start Jenkins. This is the ideal method if you're trying to set up a new Jenkins server for multiple users.

Run the following as root, or make sure your user has `sudo` permissions:
```bash
$ ./jenkins-bootstrap.sh all
```
Once complete, open your web browser to http://localhost:8080/ and login as the *admin* user (the password is stored in `/etc/bootstrap/jenkins_initial_pw`).


### Option 2. Build and run Jenkins locally

Use this script to build and run a Jenkins container as a local user, without affecting the system. This method is great for testing your Jenkins configuration locally.

Create a new file `jenkins_pw.txt` in the current directory. If this file is empty, Jenkins will prompt you to create the initial admin user. Otherwise this file's contents is the password for the *admin* user.

Run the following as a local user. Note that your user must already have access to Docker.

```bash
$ ./jenkins-bootstrap.sh docker_local_build
$ ./jenkins-bootstrap.sh docker_local_run
```

Once complete, open your web browser to http://localhost:8080/ and login as the *admin* user.


---


## Customization

You can customize most of this script's behavior in a number of ways.

First, pass an environment variable `JENKINS_FILES_DIR` whose value is the path to a directory. The default is the current directory. The files in this directory will be copied and used in various parts of the script's operation.


### Template files

If a file in *$JENKINS_FILES_DIR* (or a sub-directory) contains an extention `.tmpl`, it is considered a *template file*.

Every instance of `${{FOO}}` found in the file will be replaced with the value of an environment variable `FOO`, unless there is no such variable, in which case the original `${{FOO}}` remains. In this way you can interpolate any environment variable you want into your custom files. The default files supplied by this script are templates.


### Plugins

**All plugins are downloaded and installed into the container at build time. To update the plugins in the Jenkins Server, the container must be rebuilt.**

A default plugins list is included. You can substitute your own `plugins.txt.tmpl` or `plugins.txt` in the `JENKINS_FILES_DIR`.

The default plugins list also includes the `permissive-script-security` plugin, and attempts to enable it in the container. This should disable script security, but in practice it doesn't seem to work anymore.


### Jenkins Configuration as Code

**All configuration is copied into the container at build time. To update the Jenkins server's configuration, the container must be rebuilt.**

If you open [jenkins-bootstrap.sh](./jenkins-bootstrap.sh) you will find a Jenkins Configuration as Code *template* starting at `JCASC_CONFIG_FILE_DEFAULT='`.

This configuration does a number of things:
 - Creates an initial *admin* user.
 - Creates an initial SSH Key credential, whose value is resolved by the Configuration as Code plugin. It looks up `${BOOTSTRAP_SSH_KEY}`, which should find `/run/secrets/BOOTSTRAP_SSH_KEY`, which is volume-mounted into the container from *$SSH_KEY_FILE*. This way you can checkout Git repositories when the Jenkins server starts (just reference Jenkins credential `jenkins-bootstrap-ssh-key`).
 - Sets up a Docker Cloud with the default build agent `jenkins/jnlp-slave`. Volume-mounts into this container the `/home/jenkins/.ssh` and `/var/run/docker.sock` files, so the resulting container can both access an SSH key and run Docker commands. **Note: the Docker plugin cannot run local containers that are not in a registry, unless set the pull strategy to 'DISABLE'**
 - Tries to disable JobDSL script security. (It doesn't really work, but we set the options anyway)

The default JCasC config file created by this script is `jcasc.d/jenkins.yaml.tmpl`. To override that file, provide your own `jcasc.d/jenkins.yaml.tmpl` or `jcasc.d/jenkins.yaml` in `JENKINS_FILES_DIR`. You can also provide any other file ending in `.yaml.tmpl` or `.yaml` in a directory `jcasc.d/`, and they will be loaded by JCasC at runtime.


### SSH client configs

An initial `.ssh/known_hosts` file is generated using `ssh-keyscan github.com`. This avoids Git checkouts failing from not being able to verify the host keys. You can replace this file with an empty file in `JENKINS_FILES_DIR` to avoid this feature.

Files in `.ssh` are copied into `/var/jenkins_home/.ssh` in the container, so you can copy your own custom SSH configs there. 

**Note: only the Jenkins Controller container has these files. Build agents don't share the same filesystem.**


### Docker customizations

You can customize the containers built by this script.

The default build context of the container is a temporary directory containing the contents of the `JENKINS_FILES_DIR`. You can override this by passing the `JENKINS_DOCKER_CONTEXT` variable.

The default name and tag for the Jenkins Controller docker container can be overridden by `JENKINS_DOCKER_IMG_NAME` and `JENKINS_DOCKER_IMG_TAG` environment variables.


#### `Dockerfile`

If you open [jenkins-bootstrap.sh](./jenkins-bootstrap.sh) you will find a Dockerfile *template* starting at `JENKINS_DOCKERFILE_DEFAULT='`.

This custom Dockerfile *template* does a number of things:
 - Sets the Jenkins container base using `JENKINS_VERSION_TAG`
 - Sets the *jenkins* user's user and group ID to `LOCAL_USER_ID` & `LOCAL_GROUP_ID`
 - Creates a *docker* group and sets its group ID to `DOCKER_GID`
 - Uses a custom Dockerfile `ENTRYPOINT` to work around some file ownership issues
 - Installs some extra utilities your jobs might find useful
 - Enables *Permissive Script Security* and passes the logging properties file

You can substitute your own `Dockerfile.tmpl` or `Dockerfile` in the `JENKINS_FILES_DIR`.


#### `entrypoint.sh`

The Jenkins container's default `ENTRYPOINT` script is replaced with a modified version that can change file ownership before running Jenkins. This enables you to use a volume-mounted directory for some Jenkins files and avoid mis-matched file ownership.

You can substitute your own `entrypoint.sh.tmpl` or `entrypoint.sh` in the `JENKINS_FILES_DIR`.


### Systemd unit / Service Wrapper

If you open [jenkins-bootstrap.sh](./jenkins-bootstrap.sh) you will find a default Systemd unit file starting at `JENKINS_SYSTEMD_CONFIG_DEFAULT='`.

This unit file mostly just calls `/usr/local/bin/jenkins-svc-wrap`, so you will probably want to modify that file too. That file is found starting at `JENKINS_SVC_WRAP_DEFAULT='`.

That file also attempts to create some directories *before* starting Jenkins, and also attempts to fix file ownership (using `sudo` if possible).

 - The Jenkins Docker container is started, but only the `logs`, `jobs`, and `workspace` directories are volume-mounted in from the *$LOCAL_JENKINS_HOME* directory. This is done to avoid a particular problem when restarting or upgrading Jenkins.
   
   By default, the `JENKINS_HOME` directory Jenkins writes files to contains secrets, configuration, plugins, and other files which may need to change before the next time Jenkins is started. If these files aren't removed before Jenkins starts, they could conflict with the *Configuration as Code* you use, or cause conflicts due to incompatible versions of files between upgrades of Jenkins. To resolve these issues, we simply don't persist those files to disk. Only the `logs`, `jobs`, and `workspace` gets persisted. This way you can keep the job history and write files to a fast disk, and Jenkins doesn't blow up next time you restart it.

 - If a file pointed to by environment variable `SVC_WRAP_ENVRC` (default: `/etc/bootstrap/env`) exists, it is considered a shell script, sourced, all environment variables are `export`ed, and any lines with a '=' are considered a KEY=VALUE pair. The key name and the current value in the shell are printed out to a new temporary file, and that new temporary file is loaded into Docker with the `--env-file=` option. All of this magic is performed so that we can interpolate some variables from a file and pass them to Docker at run-time.
   
   If `SVC_WRAP_ENVRC`'s value is empty (""), the above logic doesn't happen.

 - The `/run/secrets` directory is volume-mounted into the container. This allows the *Configuration as Code* plugin to take advantage of any secrets you keep on your host.

 - The *$JENKINS_INITIAL_PW_FILE* and *$SSH_KEY_FILE* are volume-mounted into the container as `/run/secrets/JENKINS_INITIAL_PW` and `/run/secrets/BOOTSTRAP_SSH_KEY`. This way the *Configuration as Code* plugin can resolve an initial random password and an initial SSH key at start-up.

You can substitute your own `entrypoint.sh.tmpl` or `entrypoint.sh` in the `JENKINS_FILES_DIR`.

<!-- vim: syntax=markdown
-->

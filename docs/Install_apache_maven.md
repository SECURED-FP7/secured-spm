# Installing Apache Maven
1. Install the 3.2.1+ version (you can get it from [here](http://maven.apache.org/download.cgi)). 

2. Add the following env variables to `~/.bashrc`.

    ```sh
    ## Apache MAVEN ##
    export M2_HOME=/usr/local/apache-maven/apache-maven-3.2.1
    export M2=$M2_HOME/bin
    export PATH=$M2:$PATH
    ```
    **Optional:** Set the MAVEN_OPTS environment variable allowing Maven to take more memory. **This helps avoiding OutOfMemory errors**.

    Edit your `~/.bashrc` (or `~/.zshrc`, or similar depending on you shell) and add the following line:

    ```sh
    export MAVEN_OPTS="-Xms256m -Xmx1024m -XX:MaxPermSize=512m"
    ```
    > Note: syntax for setting varies on the OS used by the build machine. 


3. Set Apache Maven settings.xml file

    ```sh
    cp -n ~/.m2/settings.xml{,.orig} ; \wget -q -O - https://raw.githubusercontent.com/opendaylight/odlparent/master/settings.xml > ~/.m2/settings.xml
    ```
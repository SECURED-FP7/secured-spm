# Eclipse IDE
## Installing Eclipse IDE
Follow this steps from the OpenDaylight Wiki: [here](https://wiki.opendaylight.org/view/GettingStarted:_Eclipse#Installing_Eclipse)


## Maven projects structure
The SPM source code is divided into four diferent maven projects:

1. singleuserconflictanalysis
2. m2lservice
3. h2mservice
4. smpdist

The first three projects contain the source code of the modules. The fourth one integrates and builds the karaf osgi ODL run time framework. Thus, as we shall describe later in this document, every change made to the source code of any module will be compiled through this project.


## Importing SPM source code to Eclipse IDE
1. From Eclipse, go to File => Import => Maven => Existing Maven Projects
2. Browse to the root directory of the SPM project `<spm_repo_dir>/spm/<module_name>`
3. All of the projects should be selected by default, just click Finish

The implementation source code of each module is under the path:

* `<module-name>-impl/src/main/java/`

within the package `eu.fp7.secured.spm.<module-name>.impl` there should be at least two classes:

1. `<module-name>Provider.java`
2. `<module-name>Impl.java`

The second class is the one that implements the actual functionality of the module. Please refer to this one to modify the code.

## Compiling the SPM
1. Save all the modifications.
2. Go to `<spm_repo_dir>/spm/spmdist`
3. Compile:

    ```sh
    $ mvn clean install -DskipTests
    ```

4. Execute the controller:

    ```sh
    $ karaf/target/assembly/bin/karaf
    ```

5. Install the modules:

    SingleUserConflictAnalysis
    
    ```
    $ feature:install odl-singleuserconflictanalysis-ui
    ```
    
    Medium 2 Low servcie:
    
    ```
    $ feature:install odl-m2lservice-ui
    ```
    
    High 2 Medium servcie (Refinement service):
    
    ```
    $ feature:install odl-h2mservice-ui
    ```
    
    Wait a couple of minutes untill all the modules are loaded.
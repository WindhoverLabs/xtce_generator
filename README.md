# xtce_generator
A tool to generate xtce files from a sqlite databse. 
We follow the XTCE specifications described on **XTCE Verison 1.2** as per OMG document number:**formal/18-10-04**. You may find this document [here](https://www.omg.org/spec/XTCE/1.2/PDF).


## Dependencies
`six>=1.15.0`

**NOTE:** If you have issues running venv for python3.6 on Ubuntu 16, you should be able to fix it with this:
```
sudo apt install python3.6-venv python3.6-dev
```


## How to use 

Be sure to run this from a virtual environment:
```
python xtce_generator.py  --sqlite_path /home/vagrant/auto-yamcs/juicer/newdb --log_level ['DEBUG', 'INFO', `WARNING`, `ERROR`, `CRITICAL`, `SILENT`] --config_yaml /home/vagrant/xtce_generator/src/xtce_generator/config.yaml  --spacesystem ocpoc
```

After xtce_generator is done, you should have a file with the name of space_system_name.xml. In our case this is `ocpoc.xml` since we passed `ocpoc` as our root spacesystem.
Please beware that you may pass in any name for your spacesystem; this depends on your working context. It could be a vehicle name, machine architecture or the name of a space mission itself!


### Using The XML

The auto-generated xtce file, `ocpoc.xml` in our case, is ready for use for any ground system that is xtce-compliant. For now we use `yamcs`. Here is an example demonstrating such use:

1. Copy your xtce to your yamcs project:
```
cp ~/xtce_generator/src/ocpoc.xml /home/vagrant/yamcs-cfs/src/main/yamcs/mdb
```

2. Be sure to add this file to your `yamcs` instance file:

```
...
mdb:
    # Configuration of the active loaders
    # Valid loaders are: sheet, xtce or fully qualified name of the class
    - type: "xtce"
      spec: "mdb/cfs-ccsds.xml"
    - type: "xtce"
      spec: "mdb/CFE_EVS.xml"
    - type: "xtce"
      spec: "mdb/ocpoc.xml"

```

3. Then all you do is run yamcs!

```
mvn yamcs:run
```


## XTCE Compliance

In the future we will strive to be 100% xtce compliant. However, given that we use `yamcs` as our ground system, if there are quirks yamcs has we will be adhering to those quirks. For more info on this, you may go [here](https://docs.yamcs.org/yamcs-server-manual/mdb/loaders/xtce/).




### XTCE  Data Structures
Our xtce data structures are generated with `generateDS 2.36.2`. There is a quirk with this tool where it will be name `SpaceSystem` objects to  `SpaceSystemType` after generating the python code the xtce schema. This is very easy to fix.

Go to the `export` method of your  `SpaceSystemType`.
Change it from 
```
 def export(self, outfile, level, namespaceprefix_='', namespacedef_='', name_='SpaceSystemType', pretty_print=True):
```

to
```
 def export(self, outfile, level, namespaceprefix_='', namespacedef_='', name_='SpaceSystem', pretty_print=True):
```

After renaming that parameter, you are good to go! 
**NOTE: **Beware that if you do not change this, `yamcs` will *not* run.


Documentation updated on March 23, 2021

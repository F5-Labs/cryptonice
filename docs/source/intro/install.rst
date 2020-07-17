Install
=======

scanner.py
^^^^^^^^^^

**def scanner_driver(input_data)**

Scanner_driver is the main function of the library from which all other modules can be accessed. It will call functions to collect the requested data, based on the input provided in the input_data dictionary. As results are collected from each module, scanner_driver builds an output dictionary called scan_data with the information. This dictionary is then used to print output to the console, written to a JSON file, and returned to the function that called scanner driver (i.e. a function in another project or from a separate __main__ file).

  * *input_data*: dictionary formatted with all necessary scan information (see documentation for example)

  * *return*: dictionary of scan data, hostname

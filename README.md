# YNU Campus Network Command Client

A login Yunnan University campus network command line client. [**Supports both Windows and macOS platforms**]

### Get started

- You can perform campus network authentication by executing the following command. (On Windows and macOS
  platforms, `network.py` has been packaged and the related information is in the `pack` folder.)
    ```cmd
    network -u 1202321xxxx -p xxx12345
    ```
- Or you can run the following command. In `config.json` file, you should fill in all the necessary items to ensure that
  the program executes exactly.
  ```cmd
  network --config /.../config.json
  ```

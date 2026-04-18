@rem Gradle startup script for Windows
@rem
@rem Add default JVM options here. You can also use JAVA_OPTS and GRADLE_OPTS
@rem to pass JVM options to this script.
@set DEFAULT_JVM_OPTS="-Xmx64m" "-Xms64m"

@set APP_NAME=Gradle
@set APP_BASE_NAME=%~n0

@rem Resolve any "," in the path.
@set DIRNAME=%~dp0
@set CLASSPATH=%DIRNAME%gradle\wrapper\gradle-wrapper.jar

@set JAVA_EXE=java.exe
%JAVA_EXE% -version >NUL 2>&1
if %ERRORLEVEL% == 0 goto execute

echo. 1>&2
echo ERROR: JAVA_HOME is not set and no 'java' command could be found in your PATH. 1>&2
exit /b 1

:execute
@"%JAVA_EXE%" %DEFAULT_JVM_OPTS% %JAVA_OPTS% %GRADLE_OPTS% ^
  "-Dorg.gradle.appname=%APP_BASE_NAME%" ^
  -classpath "%CLASSPATH%" ^
  org.gradle.wrapper.GradleWrapperMain ^
  %*

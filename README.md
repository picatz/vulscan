# Vulscan

Simple, customizable vulnerability scanner that speaks [JSON](http://www.json.org/).

## Installation

    $ gem install vulscan

## Usage

Create a profile called `hello_world` which will be used to scan a host for a known "Hello World" vulnerability that has been taking over the black hat super underground china russia malware campaign. We read about it on wikipedia, the main thread intel source for anyone. :
```
$ vulscan -c hello_world --name "Hello World" --references https://en.wikipedia.org/wiki/%22Hello,_World22_program
```

Append a rule to the `hello_world` profile, looking for a known banner on port `31337`.
```
$ vulscan -a hello_world --port 31337 --string "Hello World\n"
```

Append a rule to the `hello_world` profile, looking for an API endpoint served over HTTP on port `80`.
```
$ vulscan -a hello_world --port 80 --send "GET /api/v1 HTTP/1.0\r\n\r\n" --string "{"error":true}"
```

Scan a given host, `localhost` with the `hello_world` profile we just created. Output will be JSON sperated by newlines.
```
$ vulscan -s -h localhost -p hello_world
```

## License

The gem is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).

## Code of Conduct

Everyone interacting in the Vulscan project’s codebases, issue trackers, chat rooms and mailing lists is expected to follow the [code of conduct](https://github.com/[USERNAME]/vulscan/blob/master/CODE_OF_CONDUCT.md).

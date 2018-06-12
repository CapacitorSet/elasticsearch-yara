yara-search
===========

This plugin allows ElasticSearch to filter events that match one or more [Yara](https://github.com/VirusTotal/yara) rules.

## Usage

 * A working installation of Yara is a prerequisite. Install it either through your package manager of choice or by compiling it yourself from git.

 * Download the latest zip from the [releases](https://github.com/CapacitorSet/elasticsearch-yara/releases) tab. A release is available for the latest ElasticSearch version; **if you have a different version of ElasticSearch you must compile the plugin yourself** as [required](https://www.elastic.co/guide/en/elasticsearch/plugins/master/plugin-authors.html) by ES. See the "Compiling" section for more information.

* Install the plugin: `elasticsearch-plugin install file:///path-to-the-plugin/yara-search.zip`

You can now run queries like this:

```sh
curl -X GET "localhost:9200/_search?format=yaml" -H 'Content-Type: application/json' -d '{
  "query": {
    "function_score": {
      "min_score": 1,
      "query": {
        "match_all": {}
      },
      "functions": [
        {
          "script_score": {
            "script": {
                "source": "rule HelloWorld { condition: protocol == \"tcp\" and port == 9091 }",
                "lang" : "yara",
                "params": {
                    "protocol": "",
                    "port": ""
                }
            }
          }
        }
      ]
    }
  }
}'
```

The field `source` contains the Yara rule, the `params` contain default values for variables. This is important, as Yara will throw an error if the rule contains undefined variables.

The score returned is the number of rules matched. In this case, the function will return `0.0` for items that do not match the rule, and `1.0` for items that match. The condition `"min_score": 1` prevents items that do not match the rule from occurring in the output.

## Compiling

Compiling is required if your version of ElasticSearch is different from the one this plugin is released for. This is a requirement of ElasticSearch to account for API changes.

To compile yara-search, simply install Maven and compile the plugin:

    mvn install

It will compile and package the plugin in `target/releases/yara-search-0.0.1.zip`; copy it somewhere and proceed to installation.

## Thanks

This project was developed in the context of the [Google Summer of Code](https://summerofcode.withgoogle.com/) 2018 as part of a contribution to [Honeynet](https://honeynet.org/).

Thanks to [David Pilato](http://david.pilato.fr/blog/2016/10/16/creating-a-plugin-for-elasticsearch-5-dot-0-using-maven-updated-for-ga/) for the plugin template.
elasticsearch-yara
==================

This plugin allows ElasticSearch to filter events that match one or more Yara rules.

## Usage

Download the latest zip from the [releases](https://github.com/CapacitorSet/elasticsearch-yara/releases) tab. A release is available for the latest ElasticSearch version; **if you have a different version of ElasticSearch you must compile the plugin yourself** as [required](https://www.elastic.co/guide/en/elasticsearch/plugins/master/plugin-authors.html) by ES. See the "Compiling" section for more information.

Install the plugin: `elasticsearch-plugin install file:///path-to-the-plugin/es-yara.zip`

You can now run queries like this:

```sh
curl -X GET "localhost:9200/_search?format=yaml" -H 'Content-Type: application/json' -d '{
  "query": {
    "function_score": {
      "query": {
        "match_all": {}
      },
      "functions": [
        {
          "script_score": {
            "script": {
                "source": "TODO",
                "lang" : "yara",
                "params": {
                    "TODO": "TODO"
                }
            }
          }
        }
      ]
    }
  }
}'
```

Todo: document more in detail

## Compiling

Compiling is required if your version of ElasticSearch is different from the one this plugin is released for. This is a requirement of ElasticSearch to account for API changes.

Compilation happens in two steps, compiling Yara and compiling the plugin.

Start with cloning the submodules, if you haven't already:

    git submodule update --init

Compile Yara:

    cd yara
    ./bootstrap.sh
    ./configure --with-pic
    cd ..

Install Maven and compile the plugin:

    mvn install

It will compile and package the plugin in `target/releases/elasticsearch-yara-0.0.1.zip`; copy it somewhere and proceed to installation.

## Thanks

This project was developed in the context of the [Google Summer of Code](https://summerofcode.withgoogle.com/) 2018 as part of a contribution to [Honeynet](https://honeynet.org/).

Thanks to [David Pilato](http://david.pilato.fr/blog/2016/10/16/creating-a-plugin-for-elasticsearch-5-dot-0-using-maven-updated-for-ga/) for the plugin template.
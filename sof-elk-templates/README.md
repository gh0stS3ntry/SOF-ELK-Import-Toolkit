# SOF-ELK native index templates

Unmodified copies of SOF-ELK's Elasticsearch templates from [`lib/elasticsearch_templates/`](https://github.com/philhagen/sof-elk/tree/main/lib/elasticsearch_templates) in the SOF-ELK `main` branch (the copy used as this project's reference, which targets Elasticsearch 9.4.3). SOF-ELK is GPL-3.0 licensed; these files keep its `"provider": "SOF-ELK"` metadata.

`Install-ForensicELK.ps1` loads them into a standalone Windows Elasticsearch, so indexes such as `evtxlogs-*`, `filesystem-*` and `lnkfiles-*` get the same settings and dynamic templates they would get on a SOF-ELK VM. As SOF-ELK's `supporting-scripts/load_all_dashboards.sh` does, each `component-<name>.json` is installed as component template `<name>` and each `index-<name>.json` as index template `<name>`.

`index-.kibana.json` is left out: it targets Kibana's own system index (pre-8.x saved-object types), which Elasticsearch 9 manages itself.

To refresh, copy the JSON files again from a newer SOF-ELK checkout and re-run the setup script or `forensic-elk\start.bat`.

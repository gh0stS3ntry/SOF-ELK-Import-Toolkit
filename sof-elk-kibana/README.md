# SOF-ELK out-of-box Kibana objects

Unmodified copies of SOF-ELK's Kibana Data View definitions (`kibana/data_views/*.json`) and Kibana defaults (`kibana/sof-elk_config.json`) from the SOF-ELK `main` branch (the copy used as this project's reference, which targets Elastic 9.4.3). SOF-ELK is GPL-3.0 licensed.

`SOF-ELK_CreateDataViews.py` creates these Data Views (the file name is the Data View id, as in SOF-ELK's `supporting-scripts/load_all_dashboards.sh`) and applies the settings, except `defaultRoute`, which points at a SOF-ELK dashboard that is not installed. That gives a plain Kibana, such as the one built by `Install-ForensicELK.ps1`, the same Data Views as a SOF-ELK VM. Use `--toolkit-only` to skip them.

To refresh, copy the files again from a newer SOF-ELK checkout.

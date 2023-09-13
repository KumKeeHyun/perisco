package elasticsearch

const logsIndexTemplates = `
  {
	"index_patterns": [
	  "perisco-logs-*"
	],
	"priority": 99,
	"template": {
	  "settings": {
		"number_of_shards": 1
	  },
	  "mappings": {
		"properties": {
		  "ip": {
			"properties": {
			  "client": {
				"type": "keyword"
			  },
			  "ipVersion": {
				"type": "keyword"
			  },
			  "server": {
				"type": "keyword"
			  }
			}
		  },
		  "l4": {
			"properties": {
			  "Protocol": {
				"properties": {
				  "TCP": {
					"properties": {
					  "clientPort": {
						"type": "long"
					  },
					  "serverPort": {
						"type": "long"
					  }
					}
				  }
				}
			  }
			}
		  },
		  "l7": {
			"properties": {
			  "latencyNs": {
				"type": "long"
			  },
			  "request": {
				"properties": {
				  "Record": {
					"properties": {
					  "Http": {
						"properties": {
						  "headers": {
							"properties": {
							  "key": {
								"type": "keyword"
							  },
							  "value": {
								"type": "keyword"
							  }
							}
						  },
						  "method": {
							"type": "keyword"
						  },
						  "protocol": {
							"type": "keyword"
						  },
						  "url": {
							"type": "keyword"
						  }
						}
					  }
					}
				  }
				}
			  },
			  "response": {
				"properties": {
				  "Record": {
					"properties": {
					  "Http": {
						"properties": {
						  "code": {
							"type": "long"
						  },
						  "headers": {
							"properties": {
							  "key": {
								"type": "keyword"
							  },
							  "value": {
								"type": "keyword"
							  }
							}
						  },
						  "protocol": {
							"type": "keyword"
						  }
						}
					  }
					}
				  }
				}
			  }
			}
		  },
		  "pid": {
			"type": "long"
		  },
		  "ts": {
			"type": "date"
		  }
		}
	  }
	},
	"version": 1
}
`

const k8sLogsIndexTemplates = `
  {
	"index_patterns": [
	  "perisco-k8s-logs-*"
	],
	"priority": 99,
	"template": {
	  "settings": {
		"number_of_shards": 1
	  },
	  "mappings": {
		"properties": {
		  "client": {
			"properties": {
			  "labels": {
				"type": "keyword"
			  },
			  "namespace": {
				"type": "keyword"
			  },
			  "podName": {
				"type": "keyword"
			  }
			}
		  },
		  "clientService": {
			"properties": {
			  "name": {
				"type": "keyword"
			  },
			  "namespace": {
				"type": "keyword"
			  }
			}
		  },
		  "protoMessage": {
			"properties": {
			  "ip": {
				"properties": {
				  "client": {
					"type": "keyword"
				  },
				  "ipVersion": {
					"type": "keyword"
				  },
				  "server": {
					"type": "keyword"
				  }
				}
			  },
			  "l4": {
				"properties": {
				  "Protocol": {
					"properties": {
					  "TCP": {
						"properties": {
						  "clientPort": {
							"type": "long"
						  },
						  "serverPort": {
							"type": "long"
						  }
						}
					  }
					}
				  }
				}
			  },
			  "l7": {
				"properties": {
				  "latencyNs": {
					"type": "long"
				  },
				  "request": {
					"properties": {
					  "Record": {
						"properties": {
						  "Http": {
							"properties": {
							  "headers": {
								"properties": {
								  "key": {
									"type": "keyword"
								  },
								  "value": {
									"type": "keyword"
								  }
								}
							  },
							  "method": {
								"type": "keyword"
							  },
							  "protocol": {
								"type": "keyword"
							  },
							  "url": {
								"type": "keyword"
							  }
							}
						  }
						}
					  }
					}
				  },
				  "response": {
					"properties": {
					  "Record": {
						"properties": {
						  "Http": {
							"properties": {
							  "code": {
								"type": "long"
							  },
							  "headers": {
								"properties": {
								  "key": {
									"type": "keyword"
								  },
								  "value": {
									"type": "keyword"
								  }
								}
							  },
							  "protocol": {
								"type": "keyword"
							  }
							}
						  }
						}
					  }
					}
				  }
				}
			  },
			  "pid": {
				"type": "long"
			  },
			  "ts": {
				"type": "date"
			  }
			}
		  },
		  "server": {
			"properties": {
			  "labels": {
				"type": "keyword"
			  },
			  "namespace": {
				"type": "keyword"
			  },
			  "podName": {
				"type": "keyword"
			  }
			}
		  },
		  "serverService": {
			"properties": {
			  "name": {
				"type": "keyword"
			  },
			  "namespace": {
				"type": "keyword"
			  }
			}
		  }
		}
	  }
	},
	"version": 1
  }
`

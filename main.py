from flow_generation import FlowGeneration

flow_generation = FlowGeneration(
    source="test.pcap", count=1000, output_dir="npz_s", dump="npz")
flow_generation.run()
flow_generation.summary()

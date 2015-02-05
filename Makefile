
all:
	./rebar3 compile

ct: logs 
	./rebar3 as test compile
	ct_run -dir ./test -logdir logs -pa ebin _build/lib/*/ebin
	
logs:
	mkdir -p logs

# Todos
- test coverage.
- cli tool?
  - if we use an offset file for a log, partial replication will not work. offset files expect sequential data. Or there would need to be a mapping from flume_seq to actual seq? 
  - sqlite file?
  - functions
      - publish
      - add
      - verify
- [ ] test vectors
  - 
- sql table
  - author_id
  - message_id
  - seq_num
  - is_end_of_feed 
  - payload_id
  - payload_size
  - signature 
- sizing yamf types / find some way to be able to use arrays on the stack rather than
allocating. One way would be to 
  - have yamf and signature provide constants for encoded size. This would be kinda gross as
  the yamfs get more vairants.
  - have encode_write return number of bytes written and
- replication


## Brain dump on how to get this into mobile

- how to do storage
  - maybe go with the flume arch where we have an append only log _and_ a db. The downside with this that an append only log doesn't quite fit once we get partial replication. A kv store might be better?

- how to do replication?
  - 

- how to publish and add messages
  - what does bamboo need to be able to
    - publish:
        - needs to be able to ask for a message by seq number
        - needs to be able to insert a message by seq number
        - find the next valid seq number
    - add an already published message (assuming partial replication):
        - assume we get a packet of lipmaaLinks spanning back to seq 1.
          - for each message
            - check the lipmaa is valid
            - check the previous (if we have it)
            - check the sig
            
        - needs to be able to ask for a message by seq number



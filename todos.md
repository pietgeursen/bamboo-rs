# Todos
- entry should be able to hash itself
- tidy signature of entry store
- tidy errors of yamf* and signature
- yamf_signatory has a ref to some secret bytes. They should be zeroed when dropped. The secret
should be wrapped in a type that implements drop.
- verify entry
  - lipmma links to correct seq
  - previous links to correct seq
  - payload length is correct
  - signing verifies ok
  - the author is the correct author for that feed
  - we have a complete chain of lipmaa links that get back to the first entry.
- cli tool?
  - if we use an offset file per log, partial replication will not work.
  - sqlite file?
  - functions
      - publish
      - add
      - verify
- test vectors
- sql table
  - author_id
  - message_id
  - seq_num
  - is_end_of_feed 
  - payload_id
  - payload_size
  - signature 
- sizing yamf_* types / find some way to be able to use arrays on the stack rather than
allocating. One way would be to 
  - have yamf_* and signature provide constants for encoded size. This would be kinda gross as
  the yamfs get more vairants.
  - have encode_write return number of bytes written and
- no_std
- replication
  - 



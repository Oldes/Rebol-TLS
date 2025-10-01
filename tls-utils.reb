Rebol [
    title: "TLS Utility Functions"
    file:  %tls-utils.reb
    license: MIT ;= SPDX-License-Identifier
]

cause-TLS-error: func [
    ;; Logs a TLS error and triggers a protocol-specific error event for the connection.
    name [word!]
    /local message
][
    message: replace/all form name #"_" #" "
    log-error message
    do make error! [type: 'Access id: 'Protocol arg1: message]
]

change-state: function [
    ;; Updates the TLS connection state and logs the state change for debugging and protocol tracking.
    ctx [object!]
    new-state [word!]
][
    ctx/state-prev: ctx/state
    if ctx/state <> new-state [
        log-more ["New state:^[[33m" new-state "^[[22mfrom:" ctx/state]
        ctx/state: new-state
    ]
]

assert-prev-state: function [
    ;; Ensures the previous state matches expected legal states and triggers an error otherwise.
    ctx [object!]
    legal-states [block!]
][
    ;? legal-states
    unless find legal-states ctx/state-prev [
        log-error ["State" ctx/state "is not expected after" ctx/state-prev]
        cause-TLS-error 'Internal_error
    ]
]

dispatch-event: function [
    ;; Sends an event to a target port or parent to notify of protocol-related status changes or actions.
    event  [word!]
    target [port!]
][
    log-debug ["Send-event:^[[1m" pad event 8 "^[[m->" target/spec/ref]
    either all [
        port? target/parent
        function? :target/parent/awake
    ][  ;; If there is parent scheme, send the event to its awake function 
        target/parent/awake make event! [ type: event port: target ]
    ][  ;; If not, insert the event into the system port's que
        insert system/ports/system make event! [ type: event port: target ]
    ]
]


_log-error: func[msg][
    sys/log/error 'TLS msg
]
_log-info: func[msg][
    if block? msg [msg: reform msg]
    print rejoin [" ^[[1;33m[TLS] ^[[36m" msg "^[[0m"]
]
_log-more: func[msg][
    if block? msg [msg: reform msg]
    print rejoin [" ^[[33m[TLS] ^[[0;36m" msg "^[[0m"]
]
_log-debug: func[msg][
    if block? msg [msg: reform msg]
    print rejoin [" ^[[33m[TLS] ^[[0;32m" msg "^[[0m"]
]
_log-----: :print-horizontal-line

log-error: log-info: log-more: log-debug: log-----: none

tls-verbosity: func[
    "Sets the log verbosity level for TLS-related messages and debug output."
    verbose [integer!] "Verbosity level"
][
    log-error: log-info: log-more: log-debug: log-----: none
    case/all [
        verbose >= 0 [log-error: :_log-error ]
        verbose >= 1 [log-info:  :_log-info  ]
        verbose >= 2 [log-more:  :_log-more
                      log-----:  :_log-----  ]
        verbose >= 3 [log-debug: :_log-debug ]
    ]
]

log-error: :_log-error ;- use error logs by default
;tls-verbosity 3
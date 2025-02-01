import streamlit as st

def display_multisender():
    st.markdown("<h1 style='text-align: center;'>Multi-Sender Dashboard 🚀</h1>", unsafe_allow_html=True)
    
    # Transaction Type Selector with modern tabs
    tab1, tab2, tab3 = st.tabs(["One-to-Many", "Many-to-One", "Many-to-Many"])
    
    with tab1:
        st.markdown("""
            <div style='background-color: rgba(41, 55, 240, 0.1); padding: 20px; border-radius: 10px;'>
                <h3 style='color: #2937f0;'>One-to-Many Transfer</h3>
            </div>
        """, unsafe_allow_html=True)
        source_address = st.text_input("Source Address")
        recipients = st.text_area("Recipients (One address per line)")
        amount_each = st.number_input("Amount per recipient", min_value=0.0, step=0.1)
        
        if st.button("Send One-to-Many", use_container_width=True):
            st.success("Processing One-to-Many transfer... 🚀")
            
    with tab2:
        st.markdown("""
            <div style='background-color: rgba(159, 26, 226, 0.1); padding: 20px; border-radius: 10px;'>
                <h3 style='color: #9f1ae2;'>Many-to-One Transfer</h3>
            </div>
        """, unsafe_allow_html=True)
        destination_address = st.text_input("Destination Address")
        senders = st.text_area("Senders (One address per line)")
        total_amount = st.number_input("Total Amount", min_value=0.0, step=0.1)
        
        if st.button("Send Many-to-One", use_container_width=True):
            st.success("Processing Many-to-One transfer... 💫")
            
    with tab3:
        st.markdown("""
            <div style='background-color: rgba(240, 41, 123, 0.1); padding: 20px; border-radius: 10px;'>
                <h3 style='color: #f0297b;'>Many-to-Many Transfer</h3>
            </div>
        """, unsafe_allow_html=True)
        pairs = st.text_area("Transfer Pairs (Format: sender_address,recipient_address,amount)")
        
        if st.button("Send Many-to-Many", use_container_width=True):
            st.success("Processing Many-to-Many transfer... ⚡")

    # Add transaction status and history
    st.markdown("### Recent Transactions")
    st.table({
        'Type': ['One-to-Many', 'Many-to-One', 'Many-to-Many'],
        'Status': ['Completed ✅', 'Pending ⏳', 'Processing 🔄'],
        'Amount': ['100 SOL', '50 SOL', '75 SOL']
    })
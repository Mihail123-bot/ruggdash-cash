import streamlit as st

def display_liquidity_manager():
    st.markdown("<h1 style='text-align: center;'>Liquidity Manager 💧</h1>", unsafe_allow_html=True)
    
    # Create three distinct columns for each action
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("""
            <div style='background-color: rgba(41, 55, 240, 0.1); padding: 20px; border-radius: 10px; border: 2px solid #2937f0;'>
                <h3 style='color: #2937f0; text-align: center;'>Create Liquidity</h3>
            </div>
        """, unsafe_allow_html=True)
        
        token_amount = st.number_input("Token Amount", min_value=0.0, step=0.1)
        sol_amount = st.number_input("SOL Amount", min_value=0.0, step=0.1)
        
        if st.button("Create Liquidity Pool", use_container_width=True):
            st.success("Creating liquidity pool... 🌊")
            
    with col2:
        st.markdown("""
            <div style='background-color: rgba(159, 26, 226, 0.1); padding: 20px; border-radius: 10px; border: 2px solid #9f1ae2;'>
                <h3 style='color: #9f1ae2; text-align: center;'>Remove Liquidity</h3>
            </div>
        """, unsafe_allow_html=True)
        
        remove_percentage = st.slider("Remove Percentage", 0, 100, 50)
        
        if st.button("Remove Liquidity", use_container_width=True):
            st.info(f"Removing {remove_percentage}% of liquidity... 💫")
            
    with col3:
        st.markdown("""
            <div style='background-color: rgba(240, 41, 123, 0.1); padding: 20px; border-radius: 10px; border: 2px solid #f0297b;'>
                <h3 style='color: #f0297b; text-align: center;'>Burn Liquidity</h3>
            </div>
        """, unsafe_allow_html=True)
        
        burn_amount = st.number_input("LP Tokens to Burn", min_value=0.0, step=0.1)
        
        if st.button("Burn Liquidity", use_container_width=True):
            st.warning("Burning liquidity tokens... 🔥")